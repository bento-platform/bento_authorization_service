from fastapi import APIRouter

from ..db import db

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


@grants_router.get("/")
async def list_grants():
    pass


@grants_router.post("/")
async def create_grant():
    pass


@grants_router.get("/{grant_id}")
async def get_grant(grant_id: int):
    pass


@grants_router.delete("/{grant_id}")
async def delete_grant(grant_id: int):
    pass


# EXPLICITLY: No grant updating; they are immutable.
