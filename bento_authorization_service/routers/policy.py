import asyncio
import jwt

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from typing import Callable, TypeVar

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..logger import logger
from ..models import StoredGroupModel, StoredGrantModel, ResourceModel
from ..policy_engine.evaluation import TokenData, determine_permissions, evaluate_with_provided
from ..policy_engine.permissions import Permission, PERMISSIONS_BY_STRING, P_VIEW_PERMISSIONS
from .utils import set_authz_flag, require_permission_and_flag

__all__ = ["policy_router"]

T = TypeVar("T")
U = TypeVar("U")
ResponseType = TypeVar("ResponseType", dict, BaseModel)

policy_router = APIRouter(prefix="/policy")


class ListPermissionsRequest(BaseModel):
    token_data: TokenData | None = None
    requested_resource: ResourceModel | tuple[ResourceModel, ...]


class ListPermissionsResponse(BaseModel):
    result: list[str] | list[list[str]]


def apply_scalar_or_vector(func: Callable[[T], U], v: T | tuple[T, ...]) -> U | tuple[U, ...]:
    if isinstance(v, tuple):
        return tuple(func(x) for x in v)
    return func(v)


def list_permissions_curried(
    grants: tuple[StoredGrantModel],
    groups: dict[int, StoredGroupModel],
    token_data: dict | None,
) -> Callable[[ResourceModel], list[str]]:
    def _inner(r: ResourceModel) -> list[str]:
        return sorted(
            str(p)
            for p in determine_permissions(
                grants=grants,
                groups_dict=groups,
                token_data=token_data,
                requested_resource=r,
            )
        )

    return _inner


async def use_token_data_or_return_error_state(
    authorization: OptionalBearerToken,
    idp_manager: IdPManager,
    err_state: dict,
    create_response: Callable[[dict | None], ResponseType],
) -> ResponseType:
    try:
        token_data = (await idp_manager.decode(authorization.credentials)) if authorization is not None else None
    except jwt.InvalidAudienceError as e:
        logger.warning(f"Got token with bad audience (exception: {repr(e)})")
        return err_state
    except jwt.ExpiredSignatureError:
        logger.warning(f"Got expired token")
        return err_state
    except jwt.DecodeError:
        # Actually throw an HTTP error for this one
        raise HTTPException(detail="Bearer token must be a valid JWT", status_code=status.HTTP_400_BAD_REQUEST)

    return create_response(token_data)


async def check_non_bearer_token_data_use(
    token_data: TokenData | None,
    resource: ResourceModel | tuple[ResourceModel, ...],
    request: Request,
    authorization: OptionalBearerToken,
    db: Database,
    idp_manager: IdPManager,
) -> None:
    if token_data is None:
        # Using our own token, so this becomes a public endpoint.
        set_authz_flag(request)
        return

    async def req_inner(r: ResourceModel):
        await require_permission_and_flag(r, P_VIEW_PERMISSIONS, request, authorization, db, idp_manager)

    if isinstance(resource, tuple):
        await asyncio.gather(*(req_inner(r) for r in resource))
    else:
        await req_inner(resource)


@policy_router.post("/permissions")
async def req_list_permissions(
    request: Request,
    authorization: OptionalBearerToken,
    list_permissions_request: ListPermissionsRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
) -> ListPermissionsResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = list_permissions_request.token_data
    r_resource = list_permissions_request.requested_resource

    await check_non_bearer_token_data_use(r_token_data, r_resource, request, authorization, db, idp_manager)

    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below req_evaluate() endpoint MUST be used unless for cosmetic purposes (UI rendering).
    #                                               ^^^^

    grants: tuple[StoredGrantModel]
    groups: dict[int, StoredGroupModel]
    grants, groups = await asyncio.gather(db.get_grants(), db.get_groups_dict())

    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        err_state={"result": apply_scalar_or_vector(lambda _: [], r_resource)},
        create_response=lambda token_data: ListPermissionsResponse(
            result=apply_scalar_or_vector(
                list_permissions_curried(grants, groups, token_data),
                list_permissions_request.requested_resource,
            ),
        ),
    )


class EvaluationRequest(BaseModel):
    token_data: TokenData | None = None
    requested_resource: ResourceModel | tuple[ResourceModel, ...]
    required_permissions: list[str]


class EvaluationResponse(BaseModel):
    result: bool | list[bool]


def evaluate_curried(
    grants: tuple[StoredGrantModel],
    groups: dict[int, StoredGroupModel],
    token_data: dict | None,
    required_permissions: frozenset[Permission],
) -> Callable[[ResourceModel], bool]:
    def _inner(r: ResourceModel) -> bool:
        return evaluate_with_provided(
            grants,
            groups,
            token_data,
            r,
            required_permissions,
        )

    return _inner


@policy_router.post("/evaluate")
async def req_evaluate(
    request: Request,
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
) -> EvaluationResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = evaluation_request.token_data
    r_resource = evaluation_request.requested_resource

    await check_non_bearer_token_data_use(r_token_data, r_resource, request, authorization, db, idp_manager)

    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {requested_resource: {...}, required_permissions: [...], [token_data: {...}]}

    # Given a token or token-like data, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    grants: tuple[StoredGrantModel]
    groups: dict[int, StoredGroupModel]
    grants, groups = await asyncio.gather(db.get_grants(), db.get_groups_dict())

    def _create_response(token_data: TokenData | None) -> EvaluationResponse:
        return EvaluationResponse(
            result=apply_scalar_or_vector(
                evaluate_curried(
                    grants,
                    groups,
                    r_token_data if r_token_data is not None else token_data,
                    frozenset(PERMISSIONS_BY_STRING[p] for p in evaluation_request.required_permissions),
                ),
                evaluation_request.requested_resource,
            ),
        )

    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        err_state={"result": apply_scalar_or_vector(lambda _: False, evaluation_request.requested_resource)},
        create_response=_create_response,
    )
