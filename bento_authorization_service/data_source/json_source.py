import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends
from pydantic import TypeAdapter

from bento_authorization_service.models import GrantModel, GroupModel, StoredGrantModel, StoredGroupModel

from ..config import ConfigDependency
from .base import BaseDataSource

__all__ = [
    "JsonDataSource",
    "JsonDataSourceDependency",
]

GRANTS_ADAPTER = TypeAdapter(list[GrantModel])
GROUPS_ADAPTER = TypeAdapter(list[GroupModel])


class JsonDataSource(BaseDataSource):
    @staticmethod
    def load_grants(path: Path | None) -> list[GrantModel]:
        if path:
            with open(path, "r") as fh:
                return GRANTS_ADAPTER.validate_python(json.load(fh))
        return []

    @staticmethod
    def load_groups(path: Path | None) -> list[GroupModel]:
        if path:
            with open(path, "r") as fh:
                return GROUPS_ADAPTER.validate_python(json.load(fh))
        return []

    def __init__(self, grants_path: Path | None, groups_path: Path | None):
        # TODO: figure out how to handle async initialization?
        loaded_grants = self.load_grants(grants_path)
        loaded_groups = self.load_groups(groups_path)

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
    if not config.grants_file and not config.groups_file:
        return None
    return JsonDataSource(config.grants_file, config.groups_file)


JsonDataSourceDependency = Annotated[JsonDataSource | None, Depends(get_json_data_source)]
