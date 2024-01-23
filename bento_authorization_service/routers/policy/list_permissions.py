import asyncio

from fastapi import Request
from pydantic import BaseModel

from bento_authorization_service.db import DatabaseDependency
from bento_authorization_service.dependencies import OptionalBearerToken
from bento_authorization_service.idp_manager import IdPManagerDependency
from bento_authorization_service.models import ResourceModel, StoredGrantModel, StoredGroupModel
from bento_authorization_service.policy_engine.evaluation import TokenData, determine_permissions

from .common import check_non_bearer_token_data_use, use_token_data_or_return_error_state
from .router import policy_router


class ListPermissionsRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]


class ListPermissionsResponse(BaseModel):
    result: list[list[str]]


def list_permissions_for_resource(
    grants: tuple[StoredGrantModel, ...],
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
