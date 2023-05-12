import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..logger import logger
from ..models import ResourceModel
from ..policy_engine.evaluation import evaluate
from ..policy_engine.permissions import Permission

__all__ = [
    "forbidden",
    "raise_if_no_resource_access",
    "extract_token",
    "require_permission_dependency",
    "public_endpoint_dependency",
]


def forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


async def raise_if_no_resource_access(
    request: Request,
    token: str,
    resource: ResourceModel,
    required_permission: Permission,
    db: Database,
    idp_manager: IdPManager,
) -> None:
    try:
        if not (await evaluate(idp_manager, db, token, resource, frozenset({required_permission}))):
            # Forbidden from accessing or deleting this grant
            raise forbidden()
    except HTTPException as e:
        raise e  # Pass it on
    except jwt.ExpiredSignatureError:  # Straightforward, expired token - don't bother logging
        raise forbidden()
    except Exception as e:  # Could not properly run evaluate(); return forbidden!
        logger.error(
            f"Encountered error while checking permissions for request {request.method} {request.url.path}: "
            f"{repr(e)}"
        )
        raise forbidden()


def extract_token(authorization: HTTPAuthorizationCredentials | None) -> str | None:
    return authorization.credentials if authorization is not None else None


def require_permission_dependency(resource: ResourceModel, permission: Permission):
    async def _inner(
        request: Request,
        authorization: OptionalBearerToken,
        db: DatabaseDependency,
        idp_manager: IdPManagerDependency,
    ):
        await raise_if_no_resource_access(
            request,
            extract_token(authorization),
            resource,
            permission,
            db,
            idp_manager,
        )
        # Flag that we have thought about auth
        request.state.determined_authz = True

    return Depends(_inner)


def public_endpoint(request: Request):
    # Flag that we have thought about auth
    request.state.determined_authz = True


public_endpoint_dependency = Depends(public_endpoint)
