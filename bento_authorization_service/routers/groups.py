from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from ..db import DatabaseDependency
from ..models import RESOURCE_EVERYTHING, GroupModel, StoredGroupModel
from ..policy_engine.permissions import P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS
from .utils import require_permission_dependency

__all__ = [
    "groups_router",
]

groups_router = APIRouter(prefix="/groups")


def group_not_found(group_id: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Group '{group_id}' not found")


def group_not_created() -> HTTPException:
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Group could not be created")


@groups_router.get("/", dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_VIEW_PERMISSIONS)])
async def list_groups(db: DatabaseDependency) -> list[StoredGroupModel]:
    return await db.get_groups()


@groups_router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_EDIT_PERMISSIONS)],
)
async def create_group(
    group: GroupModel,
    db: DatabaseDependency,
) -> StoredGroupModel:
    # TODO: sub-groups owned by another group
    #  - how to do nested groups only for a subset of the data / groups owned/manageable by a group or individual?
    if group.expiry is not None and group.expiry <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant is already expired")

    if (g_id := await db.create_group(group)) is not None and (created_group := await db.get_group(g_id)):
        return created_group

    raise group_not_created()


@groups_router.get("/{group_id}", dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_VIEW_PERMISSIONS)])
async def get_group(group_id: int, db: DatabaseDependency) -> StoredGroupModel:
    # TODO: sub-groups owned by another group
    # TODO: test permissions for this endpoint

    if group := await db.get_group(group_id):
        return group
    raise group_not_found(group_id)


@groups_router.delete(
    "/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_EDIT_PERMISSIONS)],
)
async def delete_group(group_id: int, db: DatabaseDependency) -> None:
    # TODO: sub-groups owned by another group
    # TODO: test permissions for this endpoint

    if (await db.get_group(group_id)) is None:
        raise group_not_found(group_id)
    await db.delete_group_and_dependent_grants(group_id)


@groups_router.put(
    "/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_permission_dependency(RESOURCE_EVERYTHING, P_EDIT_PERMISSIONS)],
)
async def update_group(group_id: int, group: GroupModel, db: DatabaseDependency) -> None:
    # TODO: sub-groups owned by another group
    # TODO: test permissions for this endpoint

    if (await db.get_group(group_id)) is None:
        raise group_not_found(group_id)
    await db.set_group(group_id, group)
