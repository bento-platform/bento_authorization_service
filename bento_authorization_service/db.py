import asyncpg
import json

from bento_lib.db.pg_async import PgAsyncDatabase
from datetime import datetime
from fastapi import Depends
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from .config import ConfigDependency
from .models import SubjectModel, ResourceModel, GrantModel, StoredGrantModel, GroupModel, StoredGroupModel
from .utils import json_model_dump_kwargs

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
    return None if r is None else SubjectModel(json.loads(r["def"]))


def resource_db_deserialize(r: asyncpg.Record | None) -> ResourceModel | None:
    return None if r is None else ResourceModel(json.loads(r["def"]))


def grant_db_deserialize(r: asyncpg.Record | None) -> StoredGrantModel | None:
    if r is None:
        return None
    return StoredGrantModel(
        id=r["id"],
        subject=SubjectModel(json.loads(r["subject"])),
        resource=ResourceModel(json.loads(r["resource"])),
        notes=r["notes"],
        created=r["created"],
        expiry=r["expiry"],
        # Aggregated from grant_permissions
        permissions=set(r["permissions"]),  # TODO: what to do with permissions class vs. string?
    )


def group_db_serialize(g: GroupModel) -> tuple[str, str, str, datetime]:
    return (
        g.name,
        json_model_dump_kwargs(g.membership, sort_keys=True),
        g.notes,
        g.expiry,
    )


def group_db_deserialize(r: asyncpg.Record | None) -> StoredGroupModel | None:
    if r is None:
        return None
    return StoredGroupModel(
        id=r["id"],
        name=r["name"],
        membership=json.loads(r["membership"]),
        notes=r["notes"],
        created=r["created"],
        expiry=r["expiry"],
    )


class Database(PgAsyncDatabase):
    def __init__(self, db_uri: str):
        super().__init__(db_uri, SCHEMA_PATH)

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
        s_ser: str = json_model_dump_kwargs(s, sort_keys=True)
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
        r_ser: str = json_model_dump_kwargs(r, sort_keys=True)
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
                    j."id" AS id, 
                    s."def" AS subject, 
                    r."def" AS resource,
                    j."notes" AS notes,
                    j."created" AS created,
                    j."expiry" AS expiry,
                    j."permissions" AS permissions
                FROM (
                    SELECT g.*, array_agg(gp."permission") AS permissions
                    FROM grants g LEFT JOIN grant_permissions gp ON g."id" = gp."grant"
                    WHERE g."id" = $1
                    GROUP BY g."id"
                ) j 
                JOIN subjects s ON j."subject" = s."id" 
                JOIN resources r ON j."resource" = r."id"
                """,
                id_,
            )
            return grant_db_deserialize(row)

    async def get_grants(self) -> tuple[StoredGrantModel, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch(
                """
                SELECT 
                    j."id" AS id, 
                    s."def" AS subject, 
                    r."def" AS resource,
                    j."notes" AS notes,
                    j."created" AS created,
                    j."expiry" AS expiry,
                    j."permissions" AS permissions
                FROM (
                    SELECT g.*, array_agg(gp."permission") AS permissions
                    FROM grants g LEFT JOIN grant_permissions gp ON g."id" = gp."grant"
                    GROUP BY g."id"
                ) j 
                JOIN subjects s ON j."subject" = s."id" 
                JOIN resources r ON j."resource" = r."id"
                """
            )
            return tuple(grant_db_deserialize(r) for r in res)

    async def create_grant(self, grant: GrantModel) -> int | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                sub_res_perm = (
                    await self.create_subject_or_get_id(grant.subject, conn),
                    await self.create_resource_or_get_id(grant.resource, conn),
                    grant.expiry,
                )

                try:
                    async with conn.transaction():
                        res: int | None = await conn.fetchval(
                            'INSERT INTO grants ("subject", "resource", "expiry", "notes") '
                            'VALUES ($1, $2, $3, $4) RETURNING "id"',
                            *sub_res_perm,
                            grant.notes,
                        )

                        assert res is not None  # Roll back transaction if insert didn't work somehow

                        await conn.executemany(
                            'INSERT INTO grant_permissions ("grant", "permission") VALUES ($1, $2)',
                            [(res, p) for p in grant.permissions],
                        )

                except AssertionError:  # Failed for some reason
                    return None

                return res

    async def add_grant_permissions(
        self, grant_id: int, permissions: frozenset[str], existing_conn: asyncpg.Connection | None = None
    ) -> None:
        conn: asyncpg.Connection
        async with self.connect(existing_conn) as conn:
            await conn.executemany(
                'INSERT INTO grant_permissions ("grant", "permission") VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [(grant_id, p) for p in permissions],
            )

    async def set_grant_permissions(self, grant_id: int, permissions: frozenset[str]) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                await conn.execute('DELETE FROM grant_permissions WHERE "grant" = $1', grant_id)
                await self.add_grant_permissions(grant_id, permissions, existing_conn=conn)

    async def delete_grant(self, grant_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)

    async def get_group(self, id_: int) -> StoredGroupModel | None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res: asyncpg.Record | None = await conn.fetchrow(
                "SELECT id, name, membership, notes, created, expiry FROM groups WHERE id = $1", id_
            )
            return group_db_deserialize(res)

    async def get_groups(self) -> tuple[StoredGroupModel, ...]:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            res = await conn.fetch("SELECT id, name, membership, notes, created, expiry FROM groups")
            return tuple(group_db_deserialize(g) for g in res)

    async def get_groups_dict(self) -> dict[int, StoredGroupModel]:
        return {g.id: g for g in (await self.get_groups())}

    async def create_group(self, group: GroupModel) -> int | None:
        # GROUP_SCHEMA_VALIDATOR.validate(group)  # Will raise if the group is invalid
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():
                return await conn.fetchval(
                    "INSERT INTO groups (name, membership, notes, expiry) VALUES ($1, $2, $3, $4) RETURNING id",
                    *group_db_serialize(group),
                )

    async def set_group(self, id_: int, group: GroupModel) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE groups SET name = $2, membership = $3, notes = $4, expiry = $5 WHERE id = $1",
                id_,
                *group_db_serialize(group),
            )

    async def delete_group_and_dependent_grants(self, group_id: int) -> None:
        conn: asyncpg.Connection
        async with self.connect() as conn:
            async with conn.transaction():  # Use a single transaction to make all deletes occur at the same time
                # The Postgres JSON access returns NULL if the field doesn't exist, so the below works.
                await conn.execute("DELETE FROM subjects WHERE (def->>'group')::int = $1", group_id)
                await conn.execute("DELETE FROM groups WHERE id = $1", group_id)


@lru_cache()
def get_db(config: ConfigDependency) -> Database:  # pragma: no cover
    return Database(config.database_uri)


DatabaseDependency = Annotated[Database, Depends(get_db)]
