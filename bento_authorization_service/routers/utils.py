from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from ..db import Database
from ..idp_manager import IdPManager
from ..models import ResourceModel
from ..policy_engine.evaluation import evaluate
from ..policy_engine.permissions import Permission

__all__ = [
    "forbidden",
    "raise_if_no_resource_access",
    "extract_token",
]


def forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


async def raise_if_no_resource_access(
    token: str,
    resource: ResourceModel,
    required_permission: Permission,
    db: Database,
    idp_manager: IdPManager,
) -> None:
    if not (await evaluate(idp_manager, db, token, resource, frozenset({required_permission}))):
        # Forbidden from accessing or deleting this grant
        raise forbidden()


def extract_token(authorization: HTTPAuthorizationCredentials | None) -> str | None:
    return authorization.credentials if authorization is not None else None
