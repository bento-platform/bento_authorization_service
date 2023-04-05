import aiofiles
import asyncpg
import contextlib

from pathlib import Path
from typing import AsyncGenerator, Optional

from .config import config

__all__ = [
    "db",
]


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseError(Exception):
    pass


class Database:
    def __init__(self, db_uri: str):
        self._db_uri = db_uri
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self):
        # Initialize the connection pool
        self._pool = await asyncpg.create_pool(self._db_uri)

        # Connect to the database and execute the schema script
        conn: asyncpg.Connection
        async with aiofiles.open(SCHEMA_PATH, "r") as sf, self.connect() as conn:
            async with conn.transaction():
                await conn.execute(await sf.read())

    async def close(self):
        if self._pool:
            await self._pool.close()

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncGenerator[asyncpg.Connection, None]:
        if self._pool is None:
            raise DatabaseError("Pool is not available")

        conn: asyncpg.Connection
        async with self._pool.acquire() as conn:
            yield conn

    async def get_grant(self, id_: int) -> Optional[dict]:  # TODO: TypedDict
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: Optional[asyncpg.Record] = await conn.fetchrow(
                "SELECT id, subject, resource, negated, permission, extra WHERE id = $1", id_)
            return dict(row) if row else None

    async def get_grants(self):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO

    async def add_grant(self, subject: dict, resource: dict, negated: bool, permission: str, extra: dict):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO

    async def get_group(self, id_: int):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO

    async def set_group(self, id_: int, membership: dict):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO


db = Database(config.database_uri)
