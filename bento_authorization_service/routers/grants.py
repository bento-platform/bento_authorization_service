from fastapi import APIRouter, HTTPException, status

from ..db import DatabaseDependency
from ..models import GrantModel
from ..types import Grant

__all__ = [
    "grants_router",
]

grants_router = APIRouter(prefix="/grants")


def grant_not_found(grant_id: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Grant '{grant_id}' not found")


def _serialize_grant(g: Grant) -> dict:
    return {**g, "permission": str(g["permission"])}


@grants_router.get("/")
async def list_grants(db: DatabaseDependency):
    return [_serialize_grant(g) for g in (await db.get_grants())]


@grants_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_grant(grant: GrantModel, db: DatabaseDependency):
    grant_model_dict = grant.dict()

    # Remove None fields (from simpler Pydantic model) if of {project: ...} type of resource
    if "project" in grant_model_dict["resource"]:
        grant_model_dict["resource"] = {k: v for k, v in grant_model_dict["resource"].items() if v is not None}

    g_id = await db.create_grant(grant_model_dict)
    if g_id is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Grant could not be created")
    return _serialize_grant(await db.get_grant(g_id))


@grants_router.get("/{grant_id}")
async def get_grant(grant_id: int, db: DatabaseDependency):
    if grant := (await db.get_grant(grant_id)):
        return _serialize_grant(grant)
    raise grant_not_found(grant_id)


@grants_router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_grant(grant_id: int, db: DatabaseDependency):
    if (await db.get_grant(grant_id)) is None:
        raise grant_not_found(grant_id)
    await db.delete_grant(grant_id)


# EXPLICITLY: No grant updating; they are immutable.x
