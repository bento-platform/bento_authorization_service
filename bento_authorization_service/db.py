import aiofiles
import asyncpg
import contextlib
import orjson

from fastapi import Depends
from functools import lru_cache
from pathlib import Path
from typing import Annotated, AsyncGenerator

from .config import ConfigDependency
from .json_schemas import (
    SUBJECT_SCHEMA_VALIDATOR,
    RESOURCE_SCHEMA_VALIDATOR,
    GROUP_SCHEMA_VALIDATOR,
    GRANT_SCHEMA_VALIDATOR,
)
from .policy_engine.permissions import PERMISSIONS_BY_STRING, Permission
from .types import Grant, Group, Subject, Resource

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


def subject_or_resource_db_serialize(obj: Subject | Resource) -> str:
    return orjson_str_dumps(obj)


def subject_db_deserialize(r: asyncpg.Record | None) -> Subject | None:
    return None if r is None else orjson.loads(r["def"])


def resource_db_deserialize(r: asyncpg.Record | None) -> Resource | None:
    return None if r is None else orjson.loads(r["def"])


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


def group_db_serialize(g: Group) -> tuple[int | None, str, str]:
    return g.get("id"), g["name"], orjson_str_dumps(g["membership"])


def group_db_deserialize(r: asyncpg.Record | None) -> Group | None:
    if r is None:
        return None
    return {"id": r["id"], "name": r["name"], "membership": orjson.loads(r["membership"])}


class Database:
    def __init__(self, db_uri: str):
        self._db_uri = db_uri
        self._pool: asyncpg.Pool | None = None

    async def initialize(self, pool_size: int = 10):
        conn: asyncpg.Connection

        if not self._pool:  # Initialize the connection pool if needed
            self._pool = await asyncpg.create_pool(self._db_uri, max_size=pool_size)

        # Connect to the database and execute the schema script
        async with aiofiles.open(SCHEMA_PATH, "r") as sf:
            async with self.connect() as conn:
                async with conn.transaction():
                    await conn.execute(await sf.read())

    async def close(self):
        if self._pool:
            await self._pool.close()
            self._pool = None

    @contextlib.asynccontextmanager
    async def connect(
        self,
        existing_conn: asyncpg.Connection | None = None,
    ) -> AsyncGenerator[asyncpg.Connection, None]:
        # TODO: raise raise DatabaseError("Pool is not available") when FastAPI has lifespan dependencies
        #  + manage pool lifespan in lifespan fn.

        if self._pool is None:
            await self.initialize()  # initialize if this is the first time we're using the pool

        if existing_conn is not None:
            yield existing_conn
            return

        conn: asyncpg.Connection
        async with self._pool.acquire() as conn:
            yield conn

    async def get_subject(self, id_: int) -> Subject | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow("SELECT def FROM subjects WHERE id = $1", id_)
            return subject_db_deserialize(row)

    async def create_subject_or_get_id(self, s: Subject, existing_conn: asyncpg.Connection | None = None) -> int | None:
        SUBJECT_SCHEMA_VALIDATOR.validate(s)
        s_ser: str = subject_or_resource_db_serialize(s)
        conn: asyncpg.Connection
        async with self.connect(existing_conn) as conn:
            if (id_ := await conn.fetchval("SELECT id FROM subjects WHERE def = $1::jsonb", s_ser)) is not None:
                # Existing subject for definition
                return id_
            return await conn.fetchval("INSERT INTO subjects (def) VALUES ($1) RETURNING id", s_ser)

    async def get_resource(self, id_: int) -> Resource | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow("SELECT def FROM resources WHERE id = $1", id_)
            return resource_db_deserialize(row)

    async def create_resource_or_get_id(
        self,
        r: Resource,
        existing_conn: asyncpg.Connection | None = None,
    ) -> int | None:
        RESOURCE_SCHEMA_VALIDATOR.validate(r)
        r_ser: str = subject_or_resource_db_serialize(r)
        conn: asyncpg.Connection
        async with self.connect(existing_conn) as conn:
            if (id_ := await conn.fetchval("SELECT id FROM resources WHERE def = $1::jsonb", r_ser)) is not None:
                # Existing resource for definition
                return id_
            return await conn.fetchval("INSERT INTO resources (def) VALUES ($1) RETURNING id", r_ser)

    async def get_grant(self, id_: int) -> Grant | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow(
                """
                SELECT 
                    g.id AS id, 
                    s.def AS subject, 
                    r.def AS resource, 
                    g.permission AS permission, 
                    g.extra AS extra
                FROM grants g 
                    JOIN subjects s  ON g.subject  = s.id
                    JOIN resources r ON g.resource = r.id 
                WHERE g.id = $1
                """, id_)
            return grant_db_deserialize(row)

    async def get_grants(self) -> tuple[Grant, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch(
                """
                SELECT 
                    g.id AS id, 
                    s.def AS subject, 
                    r.def AS resource, 
                    g.permission AS permission, 
                    g.extra AS extra
                FROM grants g 
                    JOIN subjects s  ON g.subject  = s.id
                    JOIN resources r ON g.resource = r.id
                """
            )
            return tuple(grant_db_deserialize(r) for r in res)

    async def create_grant(self, grant: Grant) -> tuple[int | None, bool]:  # id, created
        gp = grant.get("permission")
        GRANT_SCHEMA_VALIDATOR.validate({
            **grant,
            "permission": str(gp) if isinstance(gp, Permission) else gp,  # Let schema validation catch the bad type
        })  # Will raise if the group is invalid

        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                # TODO: Run DB-level checks first

                sub_res_perm = (
                    await self.create_subject_or_get_id(grant["subject"], conn),
                    await self.create_resource_or_get_id(grant["resource"], conn),
                    str(grant["permission"]),
                )

                existing_id: int | None = await conn.fetchval(
                    "SELECT id FROM grants WHERE subject = $1 AND resource = $2 AND permission = $3", *sub_res_perm)

                if existing_id is not None:
                    return existing_id, False

                res: int | None = await conn.fetchval(
                    "INSERT INTO grants (subject, resource, permission, extra) VALUES ($1, $2, $3, $4) RETURNING id",
                    *sub_res_perm, orjson_str_dumps(grant["extra"]))

                return res, res is not None

    async def delete_grant(self, grant_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)

    async def get_group(self, id_: int) -> Group | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res: asyncpg.Record | None = await conn.fetchrow(
                "SELECT id, name, membership FROM groups WHERE id = $1", id_)
            return group_db_deserialize(res)

    async def get_groups(self) -> tuple[Group, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, name, membership FROM groups")
            return tuple(group_db_deserialize(g) for g in res)

    async def get_groups_dict(self) -> dict[int, Group]:
        return {g["id"]: g for g in (await self.get_groups())}

    async def create_group(self, group: Group) -> int | None:
        GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                return await conn.fetchval(
                    "INSERT INTO groups (name, membership) VALUES ($1, $2) RETURNING id",
                    *group_db_serialize(group)[1:])

    async def set_group(self, group: Group) -> None:
        GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("UPDATE groups SET name = $2, membership = $3 WHERE id = $1", *group_db_serialize(group))

    async def delete_group_and_dependent_grants(self, group_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():  # Use a single transaction to make all deletes occur at the same time
                # The Postgres JSON access returns NULL if the field doesn't exist, so the below works.
                await conn.execute("DELETE FROM subjects WHERE (def->>'group')::int = $1",  group_id)
                await conn.execute("DELETE FROM groups WHERE id = $1", group_id)


@lru_cache()
def get_db(config: ConfigDependency) -> Database:  # pragma: no cover
    return Database(config.database_uri)


DatabaseDependency = Annotated[Database, Depends(get_db)]
