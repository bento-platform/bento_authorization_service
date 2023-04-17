from fastapi import APIRouter, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from typing import Annotated

from ..db import db
from ..models import ResourceModel
from ..policy_engine.evaluation import evaluate
from ..policy_engine.permissions import PERMISSIONS_BY_STRING

__all__ = ["policy_router"]

policy_router = APIRouter(prefix="/policy")

security = HTTPBearer()


@policy_router.post("/permissions")
async def list_permissions():
    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below evaluate() function MUST be used unless for cosmetic purposes (UI rendering).

    pass


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

    permissions = set(PERMISSIONS_BY_STRING[p] for p in evaluation_request.required_permissions)

    return {
        "result": await evaluate(
            db,
            None if authorization is None else authorization.credentials,
            evaluation_request.requested_resource.dict(),
            permissions,
        ),
    }
