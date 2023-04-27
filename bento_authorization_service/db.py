import aiofiles
import asyncpg
import contextlib
import orjson

from fastapi import Depends
from functools import lru_cache
from pathlib import Path
from typing import Annotated, AsyncGenerator, Optional

from .config import ConfigDependency
from .json_schemas import GROUP_SCHEMA_VALIDATOR, GRANT_SCHEMA_VALIDATOR
from .policy_engine.permissions import PERMISSIONS_BY_STRING, Permission
from .types import Grant, Group

__all__ = [
    "DatabaseError",
    "Database",
    "get_db",
    "DatabaseDependency",
]


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseError(Exception):
    pass


def orjson_str_dumps(obj: list | tuple | dict | int | float | str | None) -> str:
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS).decode("utf-8")


def grant_db_serialize(g: Grant) -> tuple[str, str, str, str]:
    return (
        orjson_str_dumps(g["subject"]),
        orjson_str_dumps(g["resource"]),
        str(g["permission"]),
        orjson_str_dumps(g["extra"]),
    )


def grant_db_deserialize(r: asyncpg.Record | None) -> Grant | None:
    if r is None:
        return None
    return {
        "id": r["id"],
        "subject": orjson.loads(r["subject"]),
        "resource": orjson.loads(r["resource"]),
        "permission": PERMISSIONS_BY_STRING[r["permission"]],
        "extra": orjson.loads(r["extra"]),
    }


def group_db_serialize(g: Group) -> tuple[int | None, str]:
    return g.get("id"), orjson_str_dumps(g["membership"])


def group_db_deserialize(r: asyncpg.Record | None) -> Group | None:
    if r is None:
        return None
    return {"id": r["id"], "membership": orjson.loads(r["membership"])}


class Database:
    def __init__(self, db_uri: str):
        self._db_uri = db_uri
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self):
        if self._pool:  # Already initialized
            return

        # Initialize the connection pool
        self._pool = await asyncpg.create_pool(self._db_uri)

        # Connect to the database and execute the schema script
        conn: asyncpg.Connection
        async with aiofiles.open(SCHEMA_PATH, "r") as sf:
            async with self.connect() as conn:
                async with conn.transaction():
                    await conn.execute(await sf.read())

    async def close(self):
        if self._pool:
            await self._pool.close()
            self._pool = None

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncGenerator[asyncpg.Connection, None]:
        # TODO: raise raise DatabaseError("Pool is not available") when FastAPI has lifespan dependencies
        #  + manage pool lifespan in lifespan fn.

        if self._pool is None:
            await self.initialize()  # initialize if this is the first time we're using the pool

        conn: asyncpg.Connection
        async with self._pool.acquire() as conn:
            yield conn

    async def get_grant(self, id_: int) -> Grant | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: Optional[asyncpg.Record] = await conn.fetchrow(
                "SELECT id, subject, resource, permission, extra FROM grants WHERE id = $1", id_)
            return grant_db_deserialize(row)

    async def get_grants(self) -> tuple[Grant, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, subject, resource, permission, extra FROM grants")
            return tuple(grant_db_deserialize(r) for r in res)

    async def create_grant(self, grant: Grant) -> Optional[int]:
        gp = grant.get("permission")
        GRANT_SCHEMA_VALIDATOR.validate({
            **grant,
            "permission": str(gp) if isinstance(gp, Permission) else gp,  # Let schema validation catch the bad type
        })  # Will raise if the group is invalid

        conn: asyncpg.Connection
        async with self.connect() as conn:
            # TODO: Run DB-level checks first
            return await conn.fetchval(
                "INSERT INTO grants (subject, resource, permission, extra) VALUES ($1, $2, $3, $4) RETURNING id",
                *grant_db_serialize(grant))

    async def delete_grant(self, grant_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)

    async def get_group(self, id_: int) -> Group | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res: Optional[asyncpg.Record] = await conn.fetchrow("SELECT id, membership FROM groups WHERE id = $1", id_)
            return group_db_deserialize(res)

    async def get_groups(self) -> tuple[Group, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, membership FROM groups")
            return tuple(group_db_deserialize(g) for g in res)

    async def get_groups_dict(self) -> dict[int, Group]:
        return {g["id"]: g for g in (await self.get_groups())}

    async def create_group(self, group: Group) -> Optional[int]:
        GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                return await conn.fetchval(
                    "INSERT INTO groups (membership) VALUES ($1) RETURNING id", group_db_serialize(group)[1])

    async def set_group(self, group: Group) -> None:
        GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("UPDATE groups SET membership = $2 WHERE id = $1", *group_db_serialize(group))

    async def delete_group_and_dependent_grants(self, group_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():  # Use a single transaction to make both deletes occur at the same time
                # The Postgres JSON access returns NULL if the field doesn't exist, so the below works.
                await conn.execute("DELETE FROM grants WHERE (subject->>'group')::int = $1", group_id)
                await conn.execute("DELETE FROM groups WHERE id = $1", group_id)


@lru_cache()
def get_db(config: ConfigDependency) -> Database:  # pragma: no cover
    return Database(config.database_uri)


DatabaseDependency = Annotated[Database, Depends(get_db)]
