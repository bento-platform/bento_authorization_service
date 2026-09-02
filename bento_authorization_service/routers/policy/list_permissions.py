from bento_lib.auth.helpers import valid_permissions_for_resource
from bento_lib.auth.permissions import Permission
from fastapi import Request
from pydantic import BaseModel
from structlog.stdlib import BoundLogger

from bento_authorization_service.dependencies import OptionalBearerToken
from bento_authorization_service.idp_manager import IdPManagerDependency
from bento_authorization_service.logger import LoggerDependency
from bento_authorization_service.models import ResourceModel
from bento_authorization_service.policy_engine.dependency import PolicyEngineDependency
from bento_authorization_service.policy_engine.token_data import TokenData

from ...policy_engine.base import PolicyEngine
from .common import check_non_bearer_token_data_use, use_token_data_or_return_error_state
from .router import policy_router


class ResourcesRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]


class ListPermissionsResponse(BaseModel):
    result: list[list[str]]


async def list_permissions_for_resource(
    pe: PolicyEngine, token_data: TokenData | None, r: ResourceModel, logger: BoundLogger
) -> list[str]:
    return sorted(str(p) for p in await pe.determine_permissions(r, token_data, logger))


@policy_router.post("/permissions")
async def req_list_permissions(
    request: Request,
    authorization: OptionalBearerToken,
    list_permissions_request: ResourcesRequest,
    idp_manager: IdPManagerDependency,
    logger: LoggerDependency,
    pe: PolicyEngineDependency,
) -> ListPermissionsResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission, since this is a form of token introspection, essentially.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = list_permissions_request.token_data
    r_resources = list_permissions_request.resources

    await check_non_bearer_token_data_use(r_token_data, r_resources, request, authorization, pe)

    # Request structure:
    #   Header: Authorization: Bearer <token> | None
    #   Post body: {resources: [{...}], token_data: TokenData | None}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the evaluation endpoints SHOULD be used unless necessary or for cosmetic purposes (UI rendering).

    async def _create_response(token_data: TokenData | None) -> ListPermissionsResponse:
        res = []
        for r in r_resources:
            res.append(await list_permissions_for_resource(pe, token_data, r, logger))
        return ListPermissionsResponse(result=res)

    # TODO: real error response
    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        logger,
        err_state=ListPermissionsResponse(result=[[] for _ in r_resources]),
        create_response=_create_response,
    )


class PermissionsMapResponse(BaseModel):
    result: list[dict[str, bool]]


async def build_permissions_map(
    pe: PolicyEngine,
    token_data: TokenData | None,
    resource: ResourceModel,
    logger: BoundLogger,
) -> dict[Permission, bool]:
    resource_permissions = set(await list_permissions_for_resource(pe, token_data, resource, logger))
    valid_permissions = valid_permissions_for_resource(resource.model_dump(exclude_none=True))
    return {p: p in resource_permissions for p in valid_permissions}


@policy_router.post("/permissions_map")
async def req_permissions_map(
    request: Request,
    authorization: OptionalBearerToken,
    list_permissions_request: ResourcesRequest,
    idp_manager: IdPManagerDependency,
    pe: PolicyEngineDependency,
    logger: LoggerDependency,
):
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission, since this is a form of token introspection, essentially.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    r_token_data = list_permissions_request.token_data
    r_resources = list_permissions_request.resources

    await check_non_bearer_token_data_use(r_token_data, r_resources, request, authorization, pe)

    # Request structure:
    #   Header: Authorization: Bearer <token> | None
    #   Post body: {resources: [{...}], token_data: TokenData | None}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the evaluation endpoints SHOULD be used unless necessary or for cosmetic purposes (UI rendering).

    async def _create_response(token_data: TokenData | None):
        return PermissionsMapResponse(
            result=[await build_permissions_map(pe, token_data, r, logger) for r in r_resources],
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
