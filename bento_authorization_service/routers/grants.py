from bento_lib.auth.permissions import PERMISSIONS_BY_STRING, Permission, P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS
from bento_lib.auth.helpers import permission_valid_for_resource
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, status

from ..db import Database, DatabaseDependency
from ..dependencies import OptionalBearerToken
from ..idp_manager import IdPManager, IdPManagerDependency
from ..models import GrantModel, StoredGrantModel
from ..policy_engine.evaluation import evaluate
from .utils import raise_if_no_resource_access, extract_token, public_endpoint_dependency, MarkAuthzDone

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
    MarkAuthzDone.mark_authz_done(request)
    raise grant_not_found(grant_id)


@grants_router.get("/", dependencies=[public_endpoint_dependency])
async def list_grants(
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> list[StoredGrantModel]:
    all_grants = await db.get_grants()

    resources = tuple(g.resource for g in all_grants)
    permissions = await evaluate(idp_manager, db, extract_token(authorization), resources, (P_VIEW_PERMISSIONS,))

    # For each grant in the database, check if the passed token (or the anonymous user) have "view:permissions"
    # permission on the resource in question. If so, include the grant in the response.
    return list(g for g, p in zip(all_grants, permissions) if p[0])


@grants_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_grant(
    request: Request,
    grant: GrantModel,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    authorization: OptionalBearerToken,
) -> StoredGrantModel:
    # Make sure the token is allowed to edit permissions (in this case, 'editing permissions'
    # extends to creating grants) on the resource in question.
    await raise_if_no_resource_access(
        request, extract_token(authorization), grant.resource, P_EDIT_PERMISSIONS, db, idp_manager
    )

    # Flag that we have thought about auth
    MarkAuthzDone.mark_authz_done(request)

    # Forbid creating a grant which is expired from the get-go.
    if grant.expiry is not None and grant.expiry < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant is already expired")

    for p in grant.permissions:
        if p not in PERMISSIONS_BY_STRING:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Grant specifies invalid permission {p}"
            )

        resource_dict = grant.resource.model_dump()
        if not permission_valid_for_resource(PERMISSIONS_BY_STRING[p], resource_dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Grant specifies incompatible permission {p} for resource {resource_dict}",
            )

    # Create the grant
    if (g_id := await db.create_grant(grant)) is not None:
        if (g := await db.get_grant(g_id)) is not None:
            return g  # Successfully created, return
        raise grant_could_not_be_created()  # Somehow immediately removed

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
    MarkAuthzDone.mark_authz_done(request)

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
    MarkAuthzDone.mark_authz_done(request)

    # If the above didn't raise anything, delete the grant.
    await db.delete_grant(grant_id)


# EXPLICITLY: No grant updating; they are immutable.
