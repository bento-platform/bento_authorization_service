import aiofiles
import asyncpg
import contextlib
import json

from datetime import datetime
from fastapi import Depends
from functools import lru_cache
from pathlib import Path
from typing import Annotated, AsyncGenerator

from .config import ConfigDependency
from .models import SubjectModel, ResourceModel, GrantModel, StoredGrantModel, GroupModel, StoredGroupModel

__all__ = [
    "DatabaseError",
    "Database",
    "get_db",
    "DatabaseDependency",
]


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseError(Exception):
    pass


def subject_db_deserialize(r: asyncpg.Record | None) -> SubjectModel | None:
    return None if r is None else SubjectModel(__root__=json.loads(r["def"]))


def resource_db_deserialize(r: asyncpg.Record | None) -> ResourceModel | None:
    return None if r is None else ResourceModel(__root__=json.loads(r["def"]))


def grant_db_serialize(g: GrantModel) -> tuple[str, str, str, str, datetime]:
    return (
        g.subject.json(sort_keys=True),
        g.resource.json(sort_keys=True),
        g.permission,
        json.dumps(g.extra, sort_keys=True),
        g.expiry,
    )


def grant_db_deserialize(r: asyncpg.Record | None) -> StoredGrantModel | None:
    if r is None:
        return None
    return StoredGrantModel(
        id=r["id"],
        subject=SubjectModel(__root__=json.loads(r["subject"])),
        resource=ResourceModel(__root__=json.loads(r["resource"])),
        permission=r["permission"],  # TODO: what to do with permissions class vs. string?
        extra=json.loads(r["extra"]),
        created=r["created"],
        expiry=r["expiry"],
    )


def group_db_serialize(g: GroupModel) -> tuple[str, str, datetime]:
    return (
        g.name,
        g.membership.json(sort_keys=True),
        g.expiry,
    )


def group_db_deserialize(r: asyncpg.Record | None) -> StoredGroupModel | None:
    if r is None:
        return None
    return StoredGroupModel(
        id=r["id"],
        name=r["name"],
        membership=json.loads(r["membership"]),
        created=r["created"],
        expiry=r["expiry"],
    )


class Database:
    def __init__(self, db_uri: str):
        self._db_uri: str = db_uri
        self._pool: asyncpg.Pool | None = None

    async def initialize(self, pool_size: int = 10):
        conn: asyncpg.Connection

        if not self._pool:  # Initialize the connection pool if needed
            self._pool = await asyncpg.create_pool(self._db_uri, min_size=pool_size, max_size=pool_size)

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

    async def get_subject(self, id_: int) -> SubjectModel | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow("SELECT def FROM subjects WHERE id = $1", id_)
            return subject_db_deserialize(row)

    async def create_subject_or_get_id(
        self,
        s: SubjectModel,
        existing_conn: asyncpg.Connection | None = None,
    ) -> int | None:
        s_ser: str = s.json(sort_keys=True)
        conn: asyncpg.Connection
        async with self.connect(existing_conn) as conn:
            if (id_ := await conn.fetchval("SELECT id FROM subjects WHERE def = $1::jsonb", s_ser)) is not None:
                # Existing subject for definition
                return id_
            return await conn.fetchval("INSERT INTO subjects (def) VALUES ($1) RETURNING id", s_ser)

    async def get_resource(self, id_: int) -> ResourceModel | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow("SELECT def FROM resources WHERE id = $1", id_)
            return resource_db_deserialize(row)

    async def create_resource_or_get_id(
        self,
        r: ResourceModel,
        existing_conn: asyncpg.Connection | None = None,
    ) -> int | None:
        r_ser: str = r.json(sort_keys=True)
        conn: asyncpg.Connection
        async with self.connect(existing_conn) as conn:
            if (id_ := await conn.fetchval("SELECT id FROM resources WHERE def = $1::jsonb", r_ser)) is not None:
                # Existing resource for definition
                return id_
            return await conn.fetchval("INSERT INTO resources (def) VALUES ($1) RETURNING id", r_ser)

    async def get_grant(self, id_: int) -> StoredGrantModel | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            row: asyncpg.Record | None = await conn.fetchrow(
                """
                SELECT 
                    g.id AS id, 
                    s.def AS subject, 
                    r.def AS resource, 
                    g.permission AS permission, 
                    g.extra AS extra,
                    g.created AS created,
                    g.expiry AS expiry
                FROM grants g 
                    JOIN subjects s  ON g.subject  = s.id
                    JOIN resources r ON g.resource = r.id 
                WHERE g.id = $1
                """, id_)
            return grant_db_deserialize(row)

    async def get_grants(self) -> tuple[StoredGrantModel, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch(
                """
                SELECT 
                    g.id AS id, 
                    s.def AS subject, 
                    r.def AS resource, 
                    g.permission AS permission, 
                    g.extra AS extra,
                    g.created AS created,
                    g.expiry AS expiry
                FROM grants g 
                    JOIN subjects s  ON g.subject  = s.id
                    JOIN resources r ON g.resource = r.id
                """
            )
            return tuple(grant_db_deserialize(r) for r in res)

    async def create_grant(self, grant: GrantModel) -> tuple[int | None, bool]:  # id, created
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                # TODO: Run DB-level checks first

                sub_res_perm = (
                    await self.create_subject_or_get_id(grant.subject, conn),
                    await self.create_resource_or_get_id(grant.resource, conn),
                    grant.permission,
                    grant.expiry,
                )

                # Consider an existing grant to be one which has the same subject, resource, and permission and
                # which expires at the same time or AFTER the current one being created (i.e., old outlasts new).
                existing_id: int | None = await conn.fetchval(
                    "SELECT id FROM grants WHERE subject = $1 AND resource = $2 AND permission = $3 AND expiry >= $4",
                    *sub_res_perm)

                if existing_id is not None:
                    return existing_id, False

                res: int | None = await conn.fetchval(
                    "INSERT INTO grants (subject, resource, permission, expiry, extra) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    *sub_res_perm, json.dumps(grant.extra, sort_keys=True))

                return res, res is not None

    async def delete_grant(self, grant_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)

    async def get_group(self, id_: int) -> StoredGroupModel | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res: asyncpg.Record | None = await conn.fetchrow(
                "SELECT id, name, membership, created, expiry FROM groups WHERE id = $1", id_)
            return group_db_deserialize(res)

    async def get_groups(self) -> tuple[StoredGroupModel, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, name, membership, created, expiry FROM groups")
            return tuple(group_db_deserialize(g) for g in res)

    async def get_groups_dict(self) -> dict[int, StoredGroupModel]:
        return {g.id: g for g in (await self.get_groups())}

    async def create_group(self, group: GroupModel) -> int | None:
        # GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                return await conn.fetchval(
                    "INSERT INTO groups (name, membership, expiry) VALUES ($1, $2, $3) RETURNING id",
                    *group_db_serialize(group))

    async def set_group(self, id_: int, group: GroupModel) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE groups SET name = $2, membership = $3, expiry = $4 WHERE id = $1",
                id_, *group_db_serialize(group))

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
