from fastapi import APIRouter

from ..db import db
from ..types import Grant

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


def _serialize_grant(g: Grant) -> dict:
    return {**g, "permission": str(g["permission"])}


@grants_router.get("/")
async def list_grants():
    # TODO: return typing
    return [_serialize_grant(g) for g in (await db.get_grants())]


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
