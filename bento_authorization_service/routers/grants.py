from fastapi import APIRouter, HTTPException, status

from ..db import db
from ..types import Grant

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


def grant_not_found(grant_id: int) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Grant '{grant_id}' not found")


def _serialize_grant(g: Grant) -> dict:
    return {**g, "permission": str(g["permission"])}


@grants_router.get("/")
async def list_grants():
    return [_serialize_grant(g) for g in (await db.get_grants())]


@grants_router.post("/")
async def create_grant():
    pass


@grants_router.get("/{grant_id}")
async def get_grant(grant_id: int):
    if grant := db.get_grant(grant_id):
        return _serialize_grant(grant)
    raise grant_not_found(grant_id)


@grants_router.delete("/{grant_id}")
async def delete_grant(grant_id: int):
    pass


# EXPLICITLY: No grant updating; they are immutable.
