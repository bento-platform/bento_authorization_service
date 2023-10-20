from bento_lib.auth.permissions import Permission, P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, status

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..models import RESOURCE_EVERYTHING, GrantModel, StoredGrantModel
from .utils import raise_if_no_resource_access, extract_token, require_permission_dependency, set_authz_flag

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


def grant_not_found(grant_id: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Grant '{grant_id}' not found")


def grant_could_not_be_created() -> HTTPException:
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Grant could not be created")


async def get_grant_and_check_access(
    request: Request,
    token: str,
    grant_id: int,
    required_permission: Permission,
    db: Database,
    idp_manager: IdPManager,
) -> StoredGrantModel:
    if (grant := await db.get_grant(grant_id)) is not None:
        await raise_if_no_resource_access(request, token, grant.resource, required_permission, db, idp_manager)
        return grant

    # Flag that we have thought about auth - since we are about to raise a NotFound error; consider this OK since
    # any user could theoretically see some grants.
    set_authz_flag(request)
    raise grant_not_found(grant_id)


@grants_router.get("/", dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_VIEW_PERMISSIONS)])
async def list_grants(db: DatabaseDependency) -> list[StoredGrantModel]:
    # TODO: in fact, this should only list grants which are viewable (based on the grant resource)
    #  So require_permission / similar should be called with grant.resource and P_VIEW_PERMISSIONS instead
    return await db.get_grants()


@grants_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_grant(
    request: Request,
    grant: GrantModel,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> StoredGrantModel:
    await raise_if_no_resource_access(
        request, extract_token(authorization), grant.resource, P_EDIT_PERMISSIONS, db, idp_manager
    )

    # Flag that we have thought about auth
    set_authz_flag(request)

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
    request: Request,
    grant_id: int,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> StoredGrantModel:
    # Make sure the grant exists, and we have permissions-viewing capabilities.
    grant = await get_grant_and_check_access(
        request, extract_token(authorization), grant_id, P_VIEW_PERMISSIONS, db, idp_manager
    )

    # Flag that we have thought about auth
    set_authz_flag(request)

    return grant


@grants_router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_grant(
    request: Request,
    grant_id: int,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
):
    # Make sure the grant exists, and we have permissions-editing capabilities.
    await get_grant_and_check_access(
        request, extract_token(authorization), grant_id, P_EDIT_PERMISSIONS, db, idp_manager
    )

    # Flag that we have thought about auth
    set_authz_flag(request)

    # If the above didn't raise anything, delete the grant.
    await db.delete_grant(grant_id)


# EXPLICITLY: No grant updating; they are immutable.
