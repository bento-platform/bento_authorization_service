import asyncio
import jwt

from bento_lib.auth.permissions import PERMISSIONS_BY_STRING, P_VIEW_PERMISSIONS, Permission
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from typing import Awaitable, Callable, TypeVar

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..logger import logger
from ..models import StoredGroupModel, StoredGrantModel, ResourceModel
from ..policy_engine.evaluation import TokenData, determine_permissions, evaluate
from .utils import MarkAuthzDone, require_permission_and_flag

__all__ = ["policy_router"]

T = TypeVar("T")
U = TypeVar("U")
ResponseType = TypeVar("ResponseType", dict, BaseModel)

policy_router = APIRouter(prefix="/policy")


class ListPermissionsRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]


class ListPermissionsResponse(BaseModel):
    result: list[list[str]]


def apply_scalar_or_vector(func: Callable[[T], U], v: T | tuple[T, ...]) -> U | tuple[U, ...]:
    if isinstance(v, tuple):
        return tuple(func(x) for x in v)
    return func(v)


def list_permissions_for_resource(
    grants: tuple[StoredGrantModel],
    groups: dict[int, StoredGroupModel],
    token_data: dict | None,
    r: ResourceModel,
) -> list[str]:
    return sorted(
        str(p)
        for p in determine_permissions(
            grants=grants,
            groups_dict=groups,
            token_data=token_data,
            requested_resource=r,
        )
    )


async def use_token_data_or_return_error_state(
    authorization: OptionalBearerToken,
    idp_manager: IdPManager,
    err_state: dict,
    create_response: Callable[[dict | None], Awaitable[ResponseType]],
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

    return await create_response(token_data)


async def check_non_bearer_token_data_use(
    token_data: TokenData | None,
    resources: tuple[ResourceModel, ...],
    request: Request,
    authorization: OptionalBearerToken,
    db: Database,
    idp_manager: IdPManager,
) -> None:
    if token_data is None:
        # Using our own token, so this becomes a public endpoint.
        MarkAuthzDone.mark_authz_done(request)
        return

    async def req_inner(r: ResourceModel):
        await require_permission_and_flag(r, P_VIEW_PERMISSIONS, request, authorization, db, idp_manager)

    await asyncio.gather(*map(req_inner, resources))


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
    r_resources = list_permissions_request.resources

    await check_non_bearer_token_data_use(r_token_data, r_resources, request, authorization, db, idp_manager)

    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below req_evaluate() endpoint MUST be used unless for cosmetic purposes (UI rendering).
    #                                               ^^^^

    grants: tuple[StoredGrantModel]
    groups: dict[int, StoredGroupModel]
    grants, groups = await asyncio.gather(db.get_grants(), db.get_groups_dict())

    async def _create_response(token_data: TokenData | None):
        # Not actually async, but use_token_data_or_return_error_state needs an Awaitable
        return ListPermissionsResponse(
            result=[list_permissions_for_resource(grants, groups, token_data, r) for r in r_resources],
        )

    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        err_state={"result": [list() for _ in r_resources]},
        create_response=_create_response,
    )


class EvaluationMatrixRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]
    permissions: tuple[str, ...]


class EvaluationScalarRequest(BaseModel):
    token_data: TokenData | None = None
    resource: ResourceModel
    permission: str


class EvaluationMatrixResponse(BaseModel):
    result: list[list[bool]]


class EvaluationScalarResponse(BaseModel):
    result: bool


async def _inner_req_evaluate(
    request: Request,
    authorization: OptionalBearerToken,
    req_token_data: TokenData | None,
    resources: tuple[ResourceModel, ...],
    permissions: tuple[Permission, ...],
    db: Database,
    idp_manager: IdPManager,
) -> EvaluationMatrixResponse:
    await check_non_bearer_token_data_use(req_token_data, resources, request, authorization, db, idp_manager)

    # Given a token or token-like data, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    async def _create_response(token_data: TokenData | None):
        return EvaluationMatrixResponse(result=await evaluate(idp_manager, db, token_data, resources, permissions))

    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        err_state={"result": [[False] * len(permissions) for _ in resources]},
        create_response=_create_response,
    )


@policy_router.post("/evaluate")
async def req_evaluate(
    request: Request,
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationMatrixRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
) -> EvaluationMatrixResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    # Request structure:
    #   Header: Authorization?: Bearer <token>
    #   Post body: {resources: {...}, permissions: [...], token_data?: {...}}

    return await _inner_req_evaluate(
        request,
        authorization,
        evaluation_request.token_data,
        evaluation_request.resources,
        tuple(PERMISSIONS_BY_STRING[p] for p in evaluation_request.permissions),
        db,
        idp_manager,
    )


@policy_router.post("/evaluate_one")
async def req_evaluate_one(
    request: Request,
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationScalarRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
) -> EvaluationScalarResponse:
    # Same concept as above, except with just one resource + permission. We make this a separate endpoint to help
    # prevent 'decoding' / false permissions-granting errors, where someone checks the truthiness of, e.g., [[False]],
    # which would give True when it shouldn't.

    return EvaluationScalarResponse(
        result=(
            await _inner_req_evaluate(
                request,
                authorization,
                evaluation_request.token_data,
                (evaluation_request.resource,),
                (PERMISSIONS_BY_STRING[evaluation_request.permission],),
                db,
                idp_manager,
            )
        ).result[0][0]
    )
