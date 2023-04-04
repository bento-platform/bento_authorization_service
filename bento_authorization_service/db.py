import asyncpg

from typing import Optional

from .config import config

__all__ = [
    "db",
]


class Database:
    def __init__(self, db_uri: str):
        self._db_uri = db_uri
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self):
        self._pool = await asyncpg.create_pool(self._db_uri)

    async def close(self):
        if self._pool:
            await self._pool.close()

    # TODO: Context manager for getting connections from the pool, if it's set

    async def get_grant(self, id_: int):
        pass  # TODO

    async def get_grants(self):
        pass  # TODO

    async def add_grant(self, subject: dict, resource: dict, negated: bool, permission: str, extra: dict):
        pass  # TODO

    async def get_group(self, id_: int):
        pass  # TODO

    async def set_group(self, id_: int, membership: dict):
        pass  # TODO


db = Database(config.database_uri)
