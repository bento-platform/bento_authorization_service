from fastapi import APIRouter

from ..db import db

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


@grants_router.get("/")
async def list_grants():
    pass
