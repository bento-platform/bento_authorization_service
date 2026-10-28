from pathlib import Path

from pydantic import BaseModel, Field

from bento_authorization_service.models import GrantModel, GroupModel

__all__ = [
    "StaticAuthzData",
    "load_static_authz_data",
]


class StaticAuthzData(BaseModel):
    grants: list[GrantModel] = Field(default_factory=list)
    groups: list[GroupModel] = Field(default_factory=list)


def load_static_authz_data(path: Path | None) -> tuple[list[GrantModel], list[GroupModel]]:
    if path:
        with open(path, "r") as fh:
            loaded = StaticAuthzData.model_validate_json(fh.read())
            return loaded.grants, loaded.groups
    return [], []
