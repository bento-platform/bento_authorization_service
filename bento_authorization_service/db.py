import aiofiles
import asyncpg
import contextlib
import orjson

from pathlib import Path
from typing import AsyncGenerator, Optional

from .config import config
from .policy_engine.permissions import PERMISSIONS_BY_STRING
from .types import Subject, Resource, Grant, Group

__all__ = [
    "DatabaseError",
    "Database",
    "db",
]


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseError(Exception):
    pass


def _serialize_grant(g: Grant) -> tuple[dict, dict, str, dict]:
    return g["subject"], g["resource"], str(g["permission"]), g["extra"]


def _deserialize_grant(r: asyncpg.Record | None) -> Grant | None:
    if r is None:
        return None
    return {
        "id": r["id"],
        "subject": Subject(r["subject"]),
        "resource": Resource(r["resource"]),
        "permission": PERMISSIONS_BY_STRING[r["permission"]],
        "extra": r["extra"],
    }


def _serialize_group(g: Group) -> tuple[int, str]:
    return g["id"], orjson.dumps(g["membership"]).decode("utf-8")


def _deserialize_group(r: asyncpg.Record | None) -> Group | None:
    if r is None:
        return None
    return {"id": r["id"], "membership": orjson.loads(r["membership"])}


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
                "SELECT id, subject, resource, permission, extra FROM grants WHERE id = $1", id_)
            return _deserialize_grant(row)

    async def get_grants(self) -> tuple[Grant, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, subject, resource, permission, extra FROM grants")
            return tuple(_deserialize_grant(r) for r in res)

    async def create_grant(self, grant: Grant) -> Optional[int]:
        # TODO: Run checks first

        conn: asyncpg.Connection
        async with self.connect() as conn:
            # TODO: Run DB-level checks first
            return await conn.fetchval(
                "INSERT INTO grants (subject, resource, permission, extra) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                *_serialize_grant(grant))

    async def delete_grant(self, grant_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)

    async def get_group(self, id_: int) -> Group | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res: Optional[asyncpg.Record] = await conn.fetchrow("SELECT id, membership FROM groups WHERE id = $1", id_)
            return _deserialize_group(res)

    async def get_groups(self) -> tuple[Group, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, membership FROM groups")
            return tuple(_deserialize_group(g) for g in res)

    async def get_groups_dict(self) -> dict[int, Group]:
        return {g["id"]: g for g in (await self.get_groups())}

    async def create_group(self, group: Group) -> Optional[int]:
        # TODO: Run checks first

        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                return await conn.fetchval(
                    "INSERT INTO groups (membership) VALUES ($1) RETURNING id", _serialize_group(group)[1])

    async def set_group(self, group: Group) -> None:
        # TODO: Run checks first

        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("UPDATE groups SET membership = $2 WHERE id = $1", *_serialize_group(group))

    async def delete_group_and_dependent_grants(self, group_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():  # Use a single transaction to make both deletes occur at the same time
                # The Postgres JSON access returns NULL if the field doesn't exist, so the below works.
                await conn.execute("DELETE FROM grants WHERE subject->'group' = $1", group_id)
                await conn.execute("DELETE FROM groups WHERE id = $1", group_id)


db = Database(config.database_uri)
