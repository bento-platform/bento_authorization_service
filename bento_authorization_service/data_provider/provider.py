import asyncio
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends

from ..config import ConfigDependency
from ..db import Database, DatabaseDependency
from ..models import StoredGrantModel, StoredGroupModel
from .base import BaseDataProvider
from .static_data import load_static_authz_data

__all__ = ["AuthzDataProvider", "AuthzDataProviderDependency"]


class AuthzDataProvider(BaseDataProvider):
    def __init__(self, db: Database, static_data_file: Path | None):
        self.db = db

        # TODO: figure out how to handle async initialization?
        loaded_grants, loaded_groups = load_static_authz_data(static_data_file)

        # Store static grants/groups with strictly negative integer IDs. This prevents ID clashes and means we can do
        # easy lookup routing to avoid bouncing off the database too much:

        self.static_grants: dict[int, StoredGrantModel] = {
            -1 * i: StoredGrantModel.from_grant(g, id_=-1 * i, created=datetime.now(UTC), mutable=False)
            for i, g in enumerate(loaded_grants, 1)
        }
        self.static_groups: dict[int, StoredGroupModel] = {
            -1 * i: StoredGroupModel.from_group(g, id_=-1 * i, created=datetime.now(UTC), mutable=False)
            for i, g in enumerate(loaded_groups, 1)
        }

    async def get_grant(self, id_: int) -> StoredGrantModel | None:
        if id_ >= 0:
            return await self.db.get_grant(id_)
        return self.static_grants.get(id_)

    async def get_grants(self) -> tuple[StoredGrantModel, ...]:
        return *self.static_grants.values(), *(await self.db.get_grants())

    async def get_group(self, id_: int) -> StoredGroupModel | None:
        if id_ >= 0:
            return await self.db.get_group(id_)
        return self.static_groups.get(id_)

    async def get_groups(self) -> tuple[StoredGroupModel, ...]:
        return *self.static_groups.values(), *(await self.db.get_groups())


@lru_cache
def get_authz_data_provider(config: ConfigDependency, db: DatabaseDependency) -> AuthzDataProvider:
    return AuthzDataProvider(db, config.static_authz_data)


AuthzDataProviderDependency = Annotated[AuthzDataProvider, Depends(get_authz_data_provider)]
