from fastapi import APIRouter
from pydantic import BaseModel

from ..db import DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManagerDependency
from ..models import ResourceModel
from ..policy_engine.evaluation import determine_permissions, evaluate
from ..policy_engine.permissions import PERMISSIONS_BY_STRING

__all__ = ["policy_router"]

policy_router = APIRouter(prefix="/policy")


class ListPermissionsRequest(BaseModel):
    requested_resource: ResourceModel


@policy_router.post("/permissions")
async def req_list_permissions(
    authorization: OptionalBearerToken,
    list_permissions_request: ListPermissionsRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
):
    # Endpoint permissions: available to everyone, since this endpoint's contents are token-specific.
    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below req_evaluate() endpoint MUST be used unless for cosmetic purposes (UI rendering).
    #                                               ^^^^

    return {
        "result": sorted(str(p) for p in determine_permissions(
            grants=await db.get_grants(),
            groups_dict=await db.get_groups_dict(),
            token_data=(await idp_manager.decode(authorization.credentials)) if authorization is not None else None,
            requested_resource=list_permissions_request.requested_resource,
        )),
    }


class EvaluationRequest(BaseModel):
    requested_resource: ResourceModel
    required_permissions: list[str]


@policy_router.post("/evaluate")
async def req_evaluate(
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
):
    # Endpoint permissions: available to everyone, since this endpoint's contents are token-specific.
    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {requested_resource: {...}, required_permissions: [...]}

    # Given a token, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    return {
        "result": await evaluate(
            idp_manager=idp_manager,
            db=db,
            token=None if authorization is None else authorization.credentials,
            # See https://github.com/pydantic/pydantic/discussions/4938 for below:
            requested_resource=evaluation_request.requested_resource,
            required_permissions=frozenset(PERMISSIONS_BY_STRING[p] for p in evaluation_request.required_permissions),
        ),
    }
