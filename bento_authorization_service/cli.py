import argparse
import asyncio
import sys

from . import __version__
from .config import Config, get_config
from .db import Database, get_db
from .models import GrantModel, SubjectModel, ResourceModel
from .policy_engine.permissions import PERMISSIONS, PERMISSIONS_BY_STRING


async def list_permissions(_config: Config, _db: Database, _args) -> int:
    for p in PERMISSIONS:
        print(p)
    return 0


async def list_grants(_config: Config, db: Database, _args) -> int:
    grants = await db.get_grants()

    for g in grants:
        print(g.json(sort_keys=True))

    return 0


async def create_grant(_config: Config, db: Database, args) -> int:
    g, created = await db.create_grant(
        GrantModel(
            subject=SubjectModel.parse_raw(args.subject),
            resource=ResourceModel.parse_raw(args.resource),
            expiry=None,  # TODO: support via flag
            notes=args.notes,
            permissions=frozenset(PERMISSIONS_BY_STRING[p] for p in args.permissions),
        )
    )

    if created:
        print(f"Grant successfully created: {g}")
        return 0

    print("Grant was not created.")
    return 1


async def get_grant(_config: Config, db: Database, args) -> int:
    if (g := await db.get_grant(args.id)) is not None:
        print(g.json(sort_keys=True, indent=2))
        return 0

    print("No grant found with that ID.")
    return 1


async def delete_grant(_config: Config, db: Database, args) -> int:
    id_ = args.id
    if (await db.get_grant(id_)) is None:
        print("No grant found with that ID.")
        return 1

    await db.delete_grant(id_)
    print("Done.")
    return 0


async def main(args: list[str] | None) -> int:
    args = args or sys.argv[1:]

    parser = argparse.ArgumentParser(description="CLI for the Bento Authorization service.")

    parser.add_argument("--version", "-v", action="version", version=__version__)

    subparsers = parser.add_subparsers()

    lp = subparsers.add_parser("list-permissions")
    lp.set_defaults(func=list_permissions)

    lg = subparsers.add_parser("list-grants")
    lg.set_defaults(func=list_grants)

    cg = subparsers.add_parser("create-grant")
    cg.set_defaults(func=create_grant)
    cg.add_argument("subject", type=str, help="JSON representation of the grant subject.")
    cg.add_argument("resource", type=str, help="JSON representation of the grant resource.")
    cg.add_argument("permissions", type=str, nargs="+", help="Permissions")
    cg.add_argument("--notes", type=str, default="", help="Optional human-readable notes to add to the grant.")

    gg = subparsers.add_parser("get-grant")
    gg.set_defaults(func=get_grant)
    gg.add_argument("id", type=int, help="Grant ID")

    dg = subparsers.add_parser("delete-grant")
    dg.set_defaults(func=delete_grant)
    dg.add_argument("id", type=int, help="Grant ID")

    p_args = parser.parse_args(args)
    if not getattr(p_args, "func", None):
        p_args = parser.parse_args(("--help",))

    cfg = get_config()
    return await p_args.func(cfg, get_db(cfg), p_args)


def main_sync(args: list[str] | None = None):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(main(args))


if __name__ == "__main__":
    exit(main_sync(sys.argv[1:]))
