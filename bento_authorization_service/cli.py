import argparse
import asyncio
import json
import sys
import types

from bento_lib.auth.permissions import (
    PERMISSIONS,
    PERMISSIONS_BY_STRING,
    P_QUERY_PROJECT_LEVEL_BOOLEAN,
    P_QUERY_DATASET_LEVEL_BOOLEAN,
    P_QUERY_PROJECT_LEVEL_COUNTS,
    P_QUERY_DATASET_LEVEL_COUNTS,
    P_QUERY_DATA,
)
from typing import Any, Callable, Coroutine, Literal

from . import __version__
from .config import Config, get_config
from .db import Database, get_db
from .models import GrantModel, GroupModel, SubjectModel, ResourceModel, RESOURCE_EVERYTHING, SUBJECT_EVERYONE
from .utils import json_model_dump_kwargs


ENTITIES = types.SimpleNamespace()
ENTITIES.GRANT = "grant"
ENTITIES.GROUP = "group"
GET_DELETE_ENTITIES = (ENTITIES.GRANT, ENTITIES.GROUP)


def grant_created_exit(g: int | None) -> Literal[0, 1]:
    """
    Helper function to exit with a different message/error code depending on whether the grant was successfully created.
    """
    if g is not None:
        print(f"Grant successfully created: {g}")
        return 0

    print("Grant was not created.", file=sys.stderr)
    return 1


def list_permissions_subcmd():
    """
    Sub-command of the list command, for listing all permissions (from bento_lib).
    """
    for p in PERMISSIONS:
        print(p)


async def list_grants_subcmd(db: Database):
    """
    Sub-command of the list command, for listing all grants in the database.
    """
    for g in await db.get_grants():
        print(json_model_dump_kwargs(g, sort_keys=True))


async def list_groups_subcmd(db: Database):
    """
    Sub-command of the list command, for listing all groups in the database.
    """
    for g in await db.get_groups():
        print(json_model_dump_kwargs(g, sort_keys=True))


async def list_cmd(_config: Config, db: Database, args):
    """
    Command function to list entities related to the authorization service (either as defined in code, or listed from
    the database).
    """
    match entity := getattr(args, "entity", None):
        case "permissions":
            list_permissions_subcmd()
        case "grants":
            await list_grants_subcmd(db)
        case "groups":
            await list_groups_subcmd(db)
        case _:
            print(f"Cannot list entity type: {entity}", file=sys.stderr)
            return 1
    return 0


async def create_grant_cmd(_config: Config, db: Database, args) -> int:
    """
    Command to create a grant with specified subject, resource, permissions, and optionally a note.
    """
    return grant_created_exit(
        await db.create_grant(
            GrantModel(
                subject=SubjectModel.model_validate_json(getattr(args, "subject", "null")),
                resource=ResourceModel.model_validate_json(getattr(args, "resource", "null")),
                expiry=None,  # TODO: support via flag
                notes=getattr(args, "notes", ""),
                permissions=frozenset(PERMISSIONS_BY_STRING[p] for p in args.permissions),
            )
        )
    )


async def create_group_cmd(_config: Config, db: Database, args) -> int:
    """
    Command to create a group with specified name, JSON-formatted membership, and optionally a note.
    """

    g = await db.create_group(
        GroupModel.model_validate(
            {
                "name": getattr(args, "name", "null"),
                "membership": json.loads(getattr(args, "membership", "")),
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


async def get_grant_subcmd(db: Database, id_: int) -> int:
    """
    Sub-command to retrieve and print a grant with a particular ID, or print an error if a grant with that ID does not
    exist in the database.
    """

    if (g := await db.get_grant(id_)) is not None:
        print(json_model_dump_kwargs(g, sort_keys=True, indent=2))
        return 0

    print("No grant found with that ID.", file=sys.stderr)
    return 1


async def get_group_subcmd(db: Database, id_: int) -> int:
    """
    Sub-command to retrieve and print a group with a particular ID, or print an error if a group with that ID does not
    exist in the database.
    """

    if (g := await db.get_group(id_)) is not None:
        print(json_model_dump_kwargs(g, sort_keys=True, indent=2))
        return 0

    print(f"No group found with ID: {id_}", file=sys.stderr)
    return 1


async def get_cmd(_config: Config, db: Database, args):
    id_ = getattr(args, "id", -1)
    match entity := getattr(args, "entity", None):
        case ENTITIES.GRANT:
            return await get_grant_subcmd(db, id_)
        case ENTITIES.GROUP:
            return await get_group_subcmd(db, id_)
        case _:
            print(f"Cannot get entity type: {entity}", file=sys.stderr)
            return 1


async def _delete_by_id(
    entity: str,
    id_: int,
    get_fn: Callable[[int], Coroutine[Any, Any, object | None]],
    delete_fn: Callable[[int], Coroutine[Any, Any, None]],
) -> int:
    """
    Helper function containing common logic for deleting grants/groups based on an ID, or returning an error message if
    the entity with the ID specified could not be found.
    """

    if (await get_fn(id_)) is None:
        print(f"No {entity} found with ID: {id_}")
        return 1

    await delete_fn(id_)
    print("Done.")
    return 0


async def delete_grant_subcmd(db: Database, id_: int) -> int:
    """
    Sub-command to delete a grant with the provided ID.
    """
    return await _delete_by_id(ENTITIES.GRANT, id_, db.get_grant, db.delete_grant)


async def delete_group_subcmd(db: Database, id_: int) -> int:
    """
    Sub-command to delete a group with the provided ID.
    """
    return await _delete_by_id(ENTITIES.GROUP, id_, db.get_group, db.delete_group_and_dependent_grants)


async def delete_cmd(_config: Config, db: Database, args) -> int:
    """
    Command to delete a particular entity (either a grant or a group) based on ID, or return an error message if the
    entity type or entity cannot be found.
    """

    id_ = getattr(args, "id", -1)
    match entity := getattr(args, "entity", None):
        case ENTITIES.GRANT:
            return await delete_grant_subcmd(db, id_)
        case ENTITIES.GROUP:
            return await delete_group_subcmd(db, id_)
        case _:
            print(f"Cannot delete entity type: {entity}", file=sys.stderr)
            return 1


async def add_grant_permissions_cmd(_config: Config, db: Database, args) -> int:
    """
    Command to add new permissions to an existing grant of a given ID; useful for keeping a trim, manageable set of
    grants, or for assisting in migrations when new permissions are defined.
    """

    id_ = getattr(args, "grant_id", -1)
    if (g := await db.get_grant(id_)) is not None:
        if overlap := (ps := frozenset(args.permissions)).intersection(g.permissions):
            print(f"Grant {id_} already has permissions {{{', '.join(overlap)}}}", file=sys.stderr)
        else:
            await db.add_grant_permissions(id_, ps)
        return 0

    print(f"No grant found with ID: {id_}", file=sys.stderr)
    return 1


async def set_grant_permissions_cmd(_config: Config, db: Database, args) -> int:
    """
    Command to replace the specified permissions of an existing grant of a given ID, thus altering what it grants.
    """

    id_ = getattr(args, "grant_id", -1)
    if (await db.get_grant(id_)) is not None:
        await db.set_grant_permissions(id_, frozenset(args.permissions))
        return 0

    print(f"No grant found with ID: {id_}", file=sys.stderr)
    return 1


async def assign_all_cmd(_config: Config, db: Database, args) -> int:
    """
    Special helper function to assign all permissions to a specified user. Useful for creating "superusers" which can be
    used to manage the Bento instance this authorization service is attached to.
    """
    return grant_created_exit(
        await db.create_grant(
            GrantModel(
                subject=SubjectModel.model_validate({"iss": args.iss, "sub": args.sub}),
                resource=RESOURCE_EVERYTHING,
                permissions=PERMISSIONS,
                expiry=None,
                notes="Generated by the bento_authz CLI tool as a result of `bento_authz assign-all-to-user ...`",
            )
        )
    )


async def public_data_access_cmd(_config: Config, db: Database, args) -> int:
    """
    Special helper function for the initial configuration of data access by the public ({"everyone": true}, i.e.,
    anonymous users). Depending on the level passed, either no data, censored boolean "yes/no" data, censored counts, or
    full data access will be available to everyone.
    """

    level: Literal["none", "bool", "counts", "full"] = args.level

    if level == "full":
        permissions = frozenset((P_QUERY_DATA,))
    elif level == "counts":
        permissions = frozenset((P_QUERY_PROJECT_LEVEL_COUNTS, P_QUERY_DATASET_LEVEL_COUNTS))
    elif level == "bool":  # boolean
        permissions = frozenset((P_QUERY_PROJECT_LEVEL_BOOLEAN, P_QUERY_DATASET_LEVEL_BOOLEAN))
    else:  # none
        print("Nothing to do; no access is the default state.")
        return 0

    if level == "full" and not args.force:
        confirm = input(
            "Are you sure you wish to give full data access permissions to everyone (even anonymous / signed-out "
            "users?) [y/N]"
        ).lower()

        if confirm not in ("y", "yes"):
            print("Exiting without doing anything.")
            return 0

    return grant_created_exit(
        await db.create_grant(
            GrantModel(
                subject=SUBJECT_EVERYONE,
                resource=RESOURCE_EVERYTHING,
                permissions=permissions,
                expiry=None,
                notes=(
                    f"Generated by the bento_authz CLI tool as a result of `bento_authz public-data-access {level} ...`"
                ),
            )
        )
    )


ENTITY_KWARGS = dict(type=str, help="The type of entity to list.")


async def main(args: list[str] | None, db: Database | None = None) -> int:
    cfg = get_config()
    args = args if args is not None else sys.argv[1:]
    db = db or get_db(cfg)

    parser = argparse.ArgumentParser(description="CLI for the Bento Authorization service.")

    parser.add_argument("--version", "-v", action="version", version=__version__)

    subparsers = parser.add_subparsers()

    # list -------------------------------------------------------------------------------------------------------------
    l_sub = subparsers.add_parser("list")
    l_sub.set_defaults(func=list_cmd)
    l_sub.add_argument("entity", choices=("permissions", "grants", "groups"), **ENTITY_KWARGS)
    # ------------------------------------------------------------------------------------------------------------------

    # get --------------------------------------------------------------------------------------------------------------
    g_sub = subparsers.add_parser("get")
    g_sub.set_defaults(func=get_cmd)
    g_sub.add_argument("entity", choices=GET_DELETE_ENTITIES, **ENTITY_KWARGS)
    g_sub.add_argument("id", type=int, help="Entity ID")
    # ------------------------------------------------------------------------------------------------------------------

    # create -----------------------------------------------------------------------------------------------------------

    c = subparsers.add_parser("create")
    c_subparsers = c.add_subparsers()

    cg = c_subparsers.add_parser("grant")
    cg.set_defaults(func=create_grant_cmd)
    cg.add_argument("subject", type=str, help="JSON representation of the grant subject.")
    cg.add_argument("resource", type=str, help="JSON representation of the grant resource.")
    cg.add_argument("permissions", type=str, nargs="+", help="Permissions")
    cg.add_argument("--notes", type=str, default="", help="Optional human-readable notes to add to the grant.")

    cr = c_subparsers.add_parser("group")
    cr.set_defaults(func=create_group_cmd)
    cr.add_argument("name", type=str, help="Group name.")
    cr.add_argument("membership", type=str, help="JSON representation of the group membership.")
    cr.add_argument("--notes", type=str, default="", help="Optional human-readable notes to add to the group.")

    # ------------------------------------------------------------------------------------------------------------------

    # delete -----------------------------------------------------------------------------------------------------------
    d_sub = subparsers.add_parser("delete")
    d_sub.set_defaults(func=delete_cmd)
    d_sub.add_argument("entity", choices=GET_DELETE_ENTITIES, **ENTITY_KWARGS)
    d_sub.add_argument("id", type=int, help="Entity ID")
    # ------------------------------------------------------------------------------------------------------------------

    au_sub = subparsers.add_parser(
        "assign-all-to-user",
        help='Assigns all extant permissions for {"everything": true} to an issuer + subject combination.',
    )
    au_sub.set_defaults(func=assign_all_cmd)
    au_sub.add_argument("iss", type=str, help="Issuer")
    au_sub.add_argument("sub", type=str, help="Subject ID")

    pd_sub = subparsers.add_parser(
        "public-data-access", help="Assigns a data access permission level of choice for all data to anonymous users."
    )
    pd_sub.set_defaults(func=public_data_access_cmd)
    pd_sub.add_argument("level", type=str, choices=("none", "bool", "counts", "full"), help="Data access level to give")
    pd_sub.add_argument("--force", "-f", action="store_true")

    ap_sub = subparsers.add_parser("add-grant-permissions", help="Adds permission(s) to an existing grant.")
    ap_sub.set_defaults(func=add_grant_permissions_cmd)
    ap_sub.add_argument("grant_id", type=int, help="Grant ID (use `bento_authz list` to see grants)")
    ap_sub.add_argument("permissions", type=str, nargs="+", help="Permissions")

    sp_sub = subparsers.add_parser("set-grant-permissions", help="Edits a grant to have a new set of permissions.")
    sp_sub.set_defaults(func=set_grant_permissions_cmd)
    sp_sub.add_argument("grant_id", type=int, help="Grant ID (use `bento_authz list` to see grants)")
    sp_sub.add_argument("permissions", type=str, nargs="+", help="Permissions")

    # ------------------------------------------------------------------------------------------------------------------

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
