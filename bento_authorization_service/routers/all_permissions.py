from bento_lib.auth.permissions import PERMISSIONS, Permission
from fastapi import APIRouter
from pydantic import BaseModel

from .utils import public_endpoint_dependency

__all__ = [
    "all_permissions_router",
]

all_permissions_router = APIRouter(prefix="/all_permissions")


class PermissionResponseItem(BaseModel):
    id: str
    verb: str
    noun: str
    min_level_required: str
    gives: tuple[str, ...]


def response_item_from_permission(p: Permission) -> PermissionResponseItem:
    return PermissionResponseItem(
        id=str(p),
        verb=p.verb,
        noun=p.noun,
        min_level_required=p.min_level_required,
        gives=tuple(p.gives),
    )


@all_permissions_router.get("/", dependencies=[public_endpoint_dependency])
def list_all_permissions() -> list[PermissionResponseItem]:
    return list(map(response_item_from_permission, PERMISSIONS))
