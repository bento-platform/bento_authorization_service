from fastapi import APIRouter

__all__ = [
    "groups_router",
]

groups_router = APIRouter(prefix="/groups")


@groups_router.get("/")
async def list_groups():
    pass


@groups_router.get("/{group_id}")
async def get_group(group_id: int):
    pass


@groups_router.delete("/{group_id}")
async def delete_group(group_id: int):
    # TODO: in a single transaction, delete grants which refer to the group and then delete the group.
    pass


@groups_router.put("/{group_id}")
async def update_group(group_id: int):
    pass
