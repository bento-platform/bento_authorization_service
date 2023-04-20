from fastapi import APIRouter, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from typing import Annotated

from ..db import db
from ..idp_manager import idp_manager
from ..models import ResourceModel
from ..policy_engine.evaluation import determine_permissions, evaluate
from ..policy_engine.permissions import PERMISSIONS_BY_STRING

__all__ = ["policy_router"]

policy_router = APIRouter(prefix="/policy")

security = HTTPBearer()


class ListPermissionsRequest(BaseModel):
    requested_resource: ResourceModel


@policy_router.post("/permissions")
async def req_list_permissions(
    authorization: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    list_permissions_request: ListPermissionsRequest,
):
    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below req_evaluate() endpoint MUST be used unless for cosmetic purposes (UI rendering).
    #                                               ^^^^

    token_data = (await idp_manager.decode(authorization.credentials)) if authorization is not None else None

    return {
        "result": sorted(str(p) for p in await determine_permissions(
            db, token_data, list_permissions_request.requested_resource)),
    }


class EvaluationRequest(BaseModel):
    requested_resource: ResourceModel
    required_permissions: list[str]


@policy_router.post("/evaluate")
async def req_evaluate(
    authorization: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    evaluation_request: EvaluationRequest,
):
    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {requested_resource: {...}, required_permissions: [...]}

    # Given a token, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    return {
        "result": await evaluate(
            db=db,
            token=None if authorization is None else authorization.credentials,
            requested_resource=evaluation_request.requested_resource.dict(),
            required_permissions=frozenset(PERMISSIONS_BY_STRING[p] for p in evaluation_request.required_permissions),
        ),
    }
