import argparse
import asyncio
import sys
import types

from typing import Any, Callable, Coroutine

from . import __version__
from .config import Config, get_config
from .db import Database, get_db
from .models import GrantModel, GroupModel, SubjectModel, ResourceModel
from .policy_engine.permissions import PERMISSIONS, PERMISSIONS_BY_STRING


ENTITIES = types.SimpleNamespace()
ENTITIES.GRANT = "grant"
ENTITIES.GROUP = "group"
GET_DELETE_ENTITIES = (ENTITIES.GRANT, ENTITIES.GROUP)


def list_permissions():
    for p in PERMISSIONS:
        print(p)


async def list_grants(db: Database):
    for g in await db.get_grants():
        print(g.json(sort_keys=True))


async def list_groups(db: Database):
    for g in await db.get_groups():
        print(g.json(sort_keys=True))


async def list_cmd(_config: Config, db: Database, args):
    match (entity := getattr(args, "entity", None)):
        case "permissions":
            list_permissions()
        case "grants":
            await list_grants(db)
        case "groups":
            await list_groups(db)
        case _:
            print(f"Cannot list entity type: {entity}", file=sys.stderr)
            return 1
    return 0


async def create_grant(_config: Config, db: Database, args) -> int:
    g, created = await db.create_grant(
        GrantModel(
            subject=SubjectModel.parse_raw(getattr(args, "subject", "null")),
            resource=ResourceModel.parse_raw(getattr(args, "resource", "null")),
            expiry=None,  # TODO: support via flag
            notes=getattr(args, "notes", ""),
            permissions=frozenset(PERMISSIONS_BY_STRING[p] for p in args.permissions),
        )
    )

    if created:
        print(f"Grant successfully created: {g}")
        return 0

    print("Grant was not created.", file=sys.stderr)
    return 1


async def create_group(_config: Config, db: Database, args) -> int:
    g = await db.create_group(
        GroupModel.parse_obj(
            {
                "name": getattr(args, "name", "null"),
                "membership": getattr(args, "membership", ""),
                "expiry": None,  # TODO: support via flag
                "notes": getattr(args, "notes", ""),
            }
        )
    )

    if g is not None:
        print(f"Group successfully created: {g}")
        return 0

    print("Group as not created.", file=sys.stderr)
    return 1


async def get_grant(db: Database, id_: int) -> int:
    if (g := await db.get_grant(id_)) is not None:
        print(g.json(sort_keys=True, indent=2))
        return 0

    print("No grant found with that ID.", file=sys.stderr)
    return 1


async def get_group(db: Database, id_: int) -> int:
    if (g := await db.get_group(id_)) is not None:
        print(g.json(sort_keys=True, indent=2))
        return 0

    print("No group found with that ID.", file=sys.stderr)
    return 1


async def get_cmd(_config: Config, db: Database, args):
    id_ = getattr(args, "id", -1)
    match (entity := getattr(args, "entity", None)):
        case ENTITIES.GRANT:
            return await get_grant(db, id_)
        case ENTITIES.GROUP:
            return await get_group(db, id_)
        case _:
            print(f"Cannot get entity type: {entity}", file=sys.stderr)
            return 1


async def _delete_by_id(
    entity: str,
    id_: int,
    get_fn: Callable[[int], Coroutine[Any, Any, object | None]],
    delete_fn: Callable[[int], Coroutine[Any, Any, None]],
) -> int:
    if (await get_fn(id_)) is None:
        print(f"No {entity} found with ID: {id_}")
        return 1

    await delete_fn(id_)
    print("Done.")
    return 0


async def delete_grant(db: Database, id_: int) -> int:
    return await _delete_by_id(ENTITIES.GRANT, id_, db.get_grant, db.delete_grant)


async def delete_group(db: Database, id_: int) -> int:
    return await _delete_by_id(ENTITIES.GROUP, id_, db.get_group, db.delete_group_and_dependent_grants)


async def delete_cmd(_config: Config, db: Database, args) -> int:
    id_ = getattr(args, "id", -1)
    match (entity := getattr(args, "entity", None)):
        case ENTITIES.GRANT:
            return await delete_grant(db, id_)
        case ENTITIES.GROUP:
            return await delete_group(db, id_)
        case _:
            print(f"Cannot delete entity type: {entity}", file=sys.stderr)
            return 1


async def main(args: list[str] | None, db: Database | None = None) -> int:
    cfg = get_config()
    args = args or sys.argv[1:]
    db = db or get_db(cfg)

    parser = argparse.ArgumentParser(description="CLI for the Bento Authorization service.")

    parser.add_argument("--version", "-v", action="version", version=__version__)

    subparsers = parser.add_subparsers()

    entity_kwargs = dict(type=str, help="The type of entity to list.")

    l_sub = subparsers.add_parser("list")
    l_sub.set_defaults(func=list_cmd)
    l_sub.add_argument("entity", choices=("permissions", "grants", "groups"), **entity_kwargs)

    g_sub = subparsers.add_parser("get")
    g_sub.set_defaults(func=get_cmd)
    g_sub.add_argument("entity", choices=GET_DELETE_ENTITIES, **entity_kwargs)
    g_sub.add_argument("id", type=int, help="Entity ID")

    c = subparsers.add_parser("create")
    c_subparsers = c.add_subparsers()

    cg = c_subparsers.add_parser("grant")
    cg.set_defaults(func=create_grant)
    cg.add_argument("subject", type=str, help="JSON representation of the grant subject.")
    cg.add_argument("resource", type=str, help="JSON representation of the grant resource.")
    cg.add_argument("permissions", type=str, nargs="+", help="Permissions")
    cg.add_argument("--notes", type=str, default="", help="Optional human-readable notes to add to the grant.")

    cr = c_subparsers.add_parser("group")
    cr.set_defaults(func=create_group)
    cr.add_argument("name", type=str, help="Group name.")
    cr.add_argument("membership", type=str, help="JSON representation of the group membership.")
    cr.add_argument("--notes", type=str, default="", help="Optional human-readable notes to add to the group.")

    d_sub = subparsers.add_parser("delete")
    d_sub.set_defaults(func=delete_cmd)
    d_sub.add_argument("entity", choices=GET_DELETE_ENTITIES, **entity_kwargs)
    d_sub.add_argument("id", type=int, help="Entity ID")

    p_args = parser.parse_args(args)
    if not getattr(p_args, "func", None):
        p_args = parser.parse_args(
            (
                *args,
                "--help",
            )
        )

    cfg = get_config()
    return await p_args.func(cfg, db, p_args)


def main_sync(args: list[str] | None = None):  # pragma: no cover
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(main(args))


if __name__ == "__main__":  # pragma: no cover
    exit(main_sync(sys.argv[1:]))
