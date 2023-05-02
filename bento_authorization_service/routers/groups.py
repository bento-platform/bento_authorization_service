from fastapi import APIRouter, HTTPException, status

from ..db import DatabaseDependency
from ..models import GroupModel, StoredGroupModel

__all__ = [
    "groups_router",
]

groups_router = APIRouter(prefix="/groups")


def group_not_found(group_id: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Group '{group_id}' not found")


def group_not_created() -> HTTPException:
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Group could not be created")


@groups_router.get("/")
async def list_groups(db: DatabaseDependency) -> list[StoredGroupModel]:
    return await db.get_groups()


@groups_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_group(group: GroupModel, db: DatabaseDependency) -> StoredGroupModel:
    if (g_id := await db.create_group(group)) is not None and (created_group := await db.get_group(g_id)):
        return created_group
    raise group_not_created()


@groups_router.get("/{group_id}")
async def get_group(group_id: int, db: DatabaseDependency) -> StoredGroupModel:
    if group := await db.get_group(group_id):
        return group
    raise group_not_found(group_id)


@groups_router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: int, db: DatabaseDependency):
    if (await db.get_group(group_id)) is None:
        raise group_not_found(group_id)
    await db.delete_group_and_dependent_grants(group_id)


@groups_router.put("/{group_id}")
async def update_group(group_id: int, group: GroupModel, db: DatabaseDependency):
    pass
