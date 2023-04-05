from fastapi import APIRouter

__all__ = [
    "groups_router",
]

groups_router = APIRouter(prefix="/groups")


@groups_router.get("/")
async def list_groups():
    pass
