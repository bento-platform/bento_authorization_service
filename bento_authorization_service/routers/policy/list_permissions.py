from bento_lib.auth.helpers import valid_permissions_for_resource
from bento_lib.auth.permissions import Permission
from fastapi import Request
from pydantic import BaseModel
from structlog.stdlib import BoundLogger

from bento_authorization_service.db import DatabaseDependency
from bento_authorization_service.dependencies import OptionalBearerToken
from bento_authorization_service.idp_manager import IdPManagerDependency
from bento_authorization_service.logger import LoggerDependency
from bento_authorization_service.models import ResourceModel, StoredGrantModel, StoredGroupModel
from bento_authorization_service.policy_engine.evaluation import TokenData, determine_permissions

from .common import check_non_bearer_token_data_use, use_token_data_or_return_error_state
from .router import policy_router


class ResourcesRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]


class ListPermissionsResponse(BaseModel):
    result: list[list[str]]


def list_permissions_for_resource(
    grants: tuple[StoredGrantModel, ...],
    groups: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    r: ResourceModel,
    logger: BoundLogger,
) -> list[str]:
    return sorted(
        str(p)
        for p in determine_permissions(
            grants=grants,
            groups_dict=groups,
            token_data=token_data,
            requested_resource=r,
            logger=logger,
        )
    )


@policy_router.post("/permissions")
async def req_list_permissions(
    request: Request,
    authorization: OptionalBearerToken,
    list_permissions_request: ResourcesRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    logger: LoggerDependency,
) -> ListPermissionsResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission, since this is a form of token introspection, essentially.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = list_permissions_request.token_data
    r_resources = list_permissions_request.resources

    await check_non_bearer_token_data_use(r_token_data, r_resources, request, authorization, db, idp_manager)

    # Request structure:
    #   Header: Authorization: Bearer <token> | None
    #   Post body: {resources: [{...}], token_data: TokenData | None}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the evaluation endpoints SHOULD be used unless necessary or for cosmetic purposes (UI rendering).

    async def _create_response(token_data: TokenData | None) -> ListPermissionsResponse:
        grants: tuple[StoredGrantModel, ...]
        groups: dict[int, StoredGroupModel]
        grants, groups = await db.get_grants_and_groups_dict()

        return ListPermissionsResponse(
            result=[list_permissions_for_resource(grants, groups, token_data, r, logger) for r in r_resources],
        )

    # TODO: real error response
    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        logger,
        err_state=ListPermissionsResponse(result=[list() for _ in r_resources]),
        create_response=_create_response,
    )


class PermissionsMapResponse(BaseModel):
    result: list[dict[str, bool]]


def build_permissions_map(
    grants: tuple[StoredGrantModel, ...],
    groups: dict[int, StoredGroupModel],
    token_data: TokenData,
    resource: ResourceModel,
    logger: BoundLogger,
) -> dict[Permission, bool]:
    resource_permissions = set(list_permissions_for_resource(grants, groups, token_data, resource, logger))
    valid_permissions = valid_permissions_for_resource(resource.model_dump(exclude_none=True))
    return {p: p in resource_permissions for p in valid_permissions}


@policy_router.post("/permissions_map")
async def req_permissions_map(
    request: Request,
    authorization: OptionalBearerToken,
    list_permissions_request: ResourcesRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    logger: LoggerDependency,
):
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission, since this is a form of token introspection, essentially.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = list_permissions_request.token_data
    r_resources = list_permissions_request.resources

    await check_non_bearer_token_data_use(r_token_data, r_resources, request, authorization, db, idp_manager)

    # Request structure:
    #   Header: Authorization: Bearer <token> | None
    #   Post body: {resources: [{...}], token_data: TokenData | None}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the evaluation endpoints SHOULD be used unless necessary or for cosmetic purposes (UI rendering).

    async def _create_response(token_data: TokenData | None):
        grants: tuple[StoredGrantModel, ...]
        groups: dict[int, StoredGroupModel]
        grants, groups = await db.get_grants_and_groups_dict()

        return PermissionsMapResponse(
            result=[build_permissions_map(grants, groups, token_data, r, logger) for r in r_resources],
        )

    # TODO: real error response
    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        logger,
        err_state=PermissionsMapResponse(
            result=[{p: False for p in valid_permissions_for_resource(r.model_dump())} for r in r_resources]
        ),
        create_response=_create_response,
    )
