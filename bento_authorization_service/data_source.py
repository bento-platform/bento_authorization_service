import asyncio
import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from bento_authorization_service.models import GrantModel, GroupModel, StoredGrantModel, StoredGroupModel


class BaseDataSource(ABC):
    @abstractmethod
    async def get_grant(self, id_: int) -> StoredGrantModel | None: ...

    @abstractmethod
    async def get_grants(self) -> tuple[StoredGrantModel, ...]: ...

    @abstractmethod
    async def get_group(self, id_: int) -> StoredGroupModel | None: ...

    @abstractmethod
    async def get_groups(self) -> tuple[StoredGroupModel, ...]: ...

    async def get_groups_dict(self) -> dict[int, StoredGroupModel]:
        return {g.id: g for g in (await self.get_groups())}

    async def get_grants_and_groups_dict(self) -> tuple[tuple[StoredGrantModel, ...], dict[int, StoredGroupModel]]:
        return await asyncio.gather(self.get_grants(), self.get_groups_dict())


GRANTS_ADAPTER = TypeAdapter(list[GrantModel])
GROUPS_ADAPTER = TypeAdapter(list[GroupModel])


class JsonDataSource(BaseDataSource):
    def __init__(self, grants_path: Path, groups_path: Path):
        # TODO: figure out how to handle async initialization?
        with open(grants_path, "r") as fh:
            loaded_grants = GRANTS_ADAPTER.validate_python(json.load(fh))
        with open(groups_path, "r") as fh:
            loaded_groups = GROUPS_ADAPTER.validate_python(json.load(fh))

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
