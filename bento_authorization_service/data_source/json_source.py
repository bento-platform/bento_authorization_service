from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends
from pydantic import BaseModel, Field

from bento_authorization_service.models import GrantModel, GroupModel, StoredGrantModel, StoredGroupModel

from ..config import ConfigDependency
from .base import BaseDataSource

__all__ = [
    "JsonDataSource",
    "JsonDataSourceDependency",
]


class StaticAuthzData(BaseModel):
    grants: list[GrantModel] = Field(default_factory=list)
    groups: list[GroupModel] = Field(default_factory=list)


class JsonDataSource(BaseDataSource):
    @staticmethod
    def load_data(path: Path | None) -> tuple[list[GrantModel], list[GroupModel]]:
        if path:
            with open(path, "r") as fh:
                loaded = StaticAuthzData.model_validate_json(fh.read())
                return loaded.grants, loaded.groups
        return [], []

    def __init__(self, data_path: Path):
        # TODO: figure out how to handle async initialization?
        loaded_grants, loaded_groups = self.load_data(data_path)

        self.grants: dict[int, StoredGrantModel] = {
            -1 * i: StoredGrantModel.from_grant(g, id_=-1 * i, created=datetime.now(UTC), mutable=False)
            for i, g in enumerate(loaded_grants)
        }
        self.groups: dict[int, StoredGroupModel] = {
            -1 * i: StoredGroupModel.from_group(g, id_=-1 * i, created=datetime.now(UTC), mutable=False)
            for i, g in enumerate(loaded_groups)
        }

    async def get_grant(self, id_: int) -> StoredGrantModel | None:
        return self.grants.get(id_)

    async def get_grants(self) -> tuple[StoredGrantModel, ...]:
        return tuple(self.grants.values())

    async def get_group(self, id_: int) -> StoredGroupModel | None:
        return self.groups.get(id_)

    async def get_groups(self) -> tuple[StoredGroupModel, ...]:
        return tuple(self.groups.values())


@lru_cache
def get_json_data_source(config: ConfigDependency) -> JsonDataSource | None:
    if config.static_authz_data:
        return JsonDataSource(config.static_authz_data)
    return None


JsonDataSourceDependency = Annotated[JsonDataSource | None, Depends(get_json_data_source)]
