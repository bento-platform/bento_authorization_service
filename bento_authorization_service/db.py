import aiofiles
import asyncpg
import contextlib

from pathlib import Path
from typing import AsyncGenerator, Optional

from .config import config
from .policy_engine.permissions import PERMISSIONS_BY_STRING
from .types import Subject, Resource, Grant

__all__ = [
    "Database",
    "db",
]


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseError(Exception):
    pass


def _serialize_grant(g: Grant) -> tuple[dict, dict, bool, str, dict]:
    return g["subject"], g["resource"], g["negated"], str(g["permission"]), g["extra"]


def _deserialize_grant(r: asyncpg.Record | None) -> Grant | None:
    if r is None:
        return None
    return {
        "id": r["id"],
        "subject": Subject(r["subject"]),
        "resource": Resource(r["resource"]),
        "negated": r["negated"],
        "permission": PERMISSIONS_BY_STRING[r["permission"]],
        "extra": r["extra"],
    }


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

    async def get_grant(self, id_: int) -> Grant | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: Optional[asyncpg.Record] = await conn.fetchrow(
                "SELECT id, subject, resource, negated, permission, extra FROM grants WHERE id = $1", id_)
            return _deserialize_grant(row)

    async def get_grants(self) -> tuple[Grant, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, subject, resource, negated, permission, extra FROM grants")

            # TODO: sorted!!!! by least to most specific

            return tuple(_deserialize_grant(r) for r in res)

    async def add_grant(self, grant: Grant) -> None:
        # TODO: Run checks first

        conn: asyncpg.Connection
        async with self.connect() as conn:
            # TODO: Run DB-level checks first
            await conn.execute(
                "INSERT INTO grants (subject, resource, negated, permission, extra) VALUES ($1, $2, $3, $4, $5)",
                *_serialize_grant(grant))

    async def get_group(self, id_: int):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO

    async def set_group(self, id_: int, membership: dict):
        conn: asyncpg.Connection
        async with self.connect() as conn:
            pass  # TODO


db = Database(config.database_uri)
