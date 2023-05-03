from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..models import GrantModel, StoredGrantModel, ResourceModel
from ..policy_engine.evaluation import evaluate
from ..policy_engine.permissions import Permission, P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


def extract_token(authorization: HTTPAuthorizationCredentials | None) -> str | None:
    return authorization.credentials if authorization is not None else None


def grant_not_found(grant_id: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Grant '{grant_id}' not found")


def forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def grant_could_not_be_created() -> HTTPException:
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Grant could not be created")


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


async def get_grant_and_check_access(
    token: str,
    grant_id: int,
    required_permission: Permission,
    db: Database,
    idp_manager: IdPManager,
) -> StoredGrantModel:
    if (grant := await db.get_grant(grant_id)) is not None:
        await raise_if_no_resource_access(token, grant.resource, required_permission, db, idp_manager)
        return grant
    raise grant_not_found(grant_id)


@grants_router.get("/")
async def list_grants(db: DatabaseDependency) -> list[StoredGrantModel]:
    return await db.get_grants()


@grants_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_grant(
    grant: GrantModel,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> StoredGrantModel:
    await raise_if_no_resource_access(extract_token(authorization), grant.resource, P_EDIT_PERMISSIONS, db, idp_manager)

    if grant.expiry is not None and grant.expiry < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant is already expired")

    g_id, g_created = await db.create_grant(grant)
    if g_id is not None:
        if g_created:
            if (g := await db.get_grant(g_id)) is not None:
                return g  # Successfully created, return
            raise grant_could_not_be_created()  # Somehow immediately removed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Grant with this subject + resource + permission already exists",
        )

    raise grant_could_not_be_created()


@grants_router.get("/{grant_id}")
async def get_grant(
    grant_id: int,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> StoredGrantModel:
    # Make sure the grant exists, and we have permissions-viewing capabilities, then return a serialized version.
    return await get_grant_and_check_access(extract_token(authorization), grant_id, P_VIEW_PERMISSIONS, db, idp_manager)


@grants_router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_grant(
    grant_id: int,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
):
    # Make sure the grant exists, and we have permissions-editing capabilities.
    await get_grant_and_check_access(extract_token(authorization), grant_id, P_EDIT_PERMISSIONS, db, idp_manager)

    # If the above didn't raise anything, delete the grant.
    await db.delete_grant(grant_id)


# EXPLICITLY: No grant updating; they are immutable.
