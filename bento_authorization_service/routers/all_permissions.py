from bento_lib.auth.permissions import PERMISSIONS, Permission
from fastapi import APIRouter, Response
from pydantic import BaseModel

from ..authz import authz_middleware

__all__ = [
    "all_permissions_router",
]

all_permissions_router = APIRouter(prefix="/all_permissions")


class PermissionResponseItem(BaseModel):
    id: str
    verb: str
    noun: str
    min_level_required: str
    supports_data_type_narrowing: bool
    gives: tuple[str, ...]


def response_item_from_permission(p: Permission) -> PermissionResponseItem:
    return PermissionResponseItem(
        id=str(p),
        verb=p.verb,
        noun=p.noun,
        min_level_required=p.min_level_required,
        supports_data_type_narrowing=p.supports_data_type_narrowing,
        gives=tuple(p.gives),
    )


@all_permissions_router.get("/", dependencies=[authz_middleware.dep_public_endpoint()])
def list_all_permissions(response: Response) -> list[PermissionResponseItem]:
    # unchanging public JSON served; cache for a day:
    response.headers["Cache-Control"] = "public, max-age=86400"
    return list(map(response_item_from_permission, PERMISSIONS))
