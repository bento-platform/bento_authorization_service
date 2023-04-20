from fastapi import APIRouter, HTTPException

from ..db import db

__all__ = [
    "groups_router",
]

groups_router = APIRouter(prefix="/groups")


def group_not_found(group_id: int) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Group '{group_id}' not found")


@groups_router.get("/")
async def list_groups():
    return await db.get_groups()


@groups_router.get("/{group_id}")
async def get_group(group_id: int):
    if group := await db.get_group(group_id):
        return group
    raise group_not_found(group_id)


@groups_router.delete("/{group_id}")
async def delete_group(group_id: int):
    # TODO: in a single transaction, delete grants which refer to the group and then delete the group.
    pass


@groups_router.put("/{group_id}")
async def update_group(group_id: int):
    pass
