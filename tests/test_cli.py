import io

import pytest

from bento_lib.auth.permissions import (
    PERMISSIONS,
    P_QUERY_DATA,
    P_INGEST_DATA,
    P_QUERY_PROJECT_LEVEL_BOOLEAN,
    P_QUERY_DATASET_LEVEL_BOOLEAN,
    P_QUERY_PROJECT_LEVEL_COUNTS,
    P_QUERY_DATASET_LEVEL_COUNTS,
    Permission,
)

from bento_authorization_service import cli
from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database
from bento_authorization_service.utils import json_model_dump_kwargs

from . import shared_data as sd


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_bad_entity(db: Database, db_cleanup):
    class Args:
        def __init__(self):
            self.entity = "abc"

    assert (await cli.list_cmd(get_config(), db, object())) == 1
    assert (await cli.list_cmd(get_config(), db, Args())) == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_permissions(capsys, db: Database, db_cleanup):
    await cli.main(["list", "permissions"], db=db)
    captured = capsys.readouterr()
    assert captured.out == "\n".join(PERMISSIONS) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_grants(capsys, db: Database, db_cleanup):
    await cli.main(["list", "grants"], db=db)
    captured = capsys.readouterr()

    # Default grant set for testing purposes:
    assert (
        captured.out
        == "\n".join(map(lambda x: json_model_dump_kwargs(x, sort_keys=True), await db.get_grants())) + "\n"
    )


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_groups_none(capsys, db: Database, db_cleanup):
    await cli.main(["list", "groups"], db=db)
    captured = capsys.readouterr()

    # No groups by default:
    assert captured.out == ""


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_groups_one(capsys, db: Database, db_cleanup):
    grp = sd.TEST_GROUPS[0][0]

    # Create a group
    g_id = await db.create_group(grp)

    # List all groups
    await cli.main(["list", "groups"], db=db)
    captured = capsys.readouterr()

    # One group by default:
    assert captured.out == json_model_dump_kwargs((await db.get_group(g_id)), sort_keys=True) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_get_bad_entity(db: Database, db_cleanup):
    class Args:
        def __init__(self):
            self.entity = "abc"

    assert (await cli.get_cmd(get_config(), db, object())) == 1
    assert (await cli.get_cmd(get_config(), db, Args())) == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_create_group(capsys, db: Database, db_cleanup):
    grp = sd.TEST_GROUPS[0][0]

    # Try creating the group via CLI
    r = await cli.main(["create", "group", grp.name, grp.membership.model_dump_json(), "--note", "note"])
    assert r == 0

    # Make sure the group exists in the database
    captured = capsys.readouterr()
    new_id = int(captured.out.strip().split(" ")[-1])

    assert len(await db.get_groups()) == 1  # 1 group, the one we just created

    # check we can get the group
    assert await db.get_group(new_id) is not None


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_get_group(capsys, db: Database, db_cleanup):
    grp = sd.TEST_GROUPS[0][0]

    # Create a group
    g_id = await db.create_group(grp)

    # Get the group
    assert (await cli.main(["get", "group", str(g_id)], db=db)) == 0
    captured = capsys.readouterr()

    # One group by default:
    assert captured.out == json_model_dump_kwargs((await db.get_group(g_id)), sort_keys=True, indent=2) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_get_group_dne(capsys, db: Database, db_cleanup):
    # Get a group which DNE
    assert (await cli.main(["get", "group", "0"], db=db)) == 1
    captured = capsys.readouterr()
    assert "No group" in captured.err


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_create_grant(capsys, db: Database, db_cleanup):
    r = await cli.main(
        [
            "create",
            "grant",
            sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.subject.model_dump_json(),
            sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.resource.model_dump_json(exclude_none=True),
            *sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.permissions,
        ],
        db=db,
    )

    assert r == 0

    captured = capsys.readouterr()
    new_id = int(captured.out.strip().split(" ")[-1])

    # 2 test initial grants + 1 new one
    assert len(await db.get_grants()) == 2

    # check we can get the grant
    assert await db.get_grant(new_id) is not None


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_get_grant(capsys, db: Database, db_cleanup):
    existing_grant = (await db.get_grants())[0]

    r = await cli.main(["get", "grant", str(existing_grant.id)], db=db)
    assert r == 0
    captured = capsys.readouterr()
    assert captured.out == json_model_dump_kwargs(existing_grant, sort_keys=True, indent=2) + "\n"

    r = await cli.main(["get", "grant", "0"])  # DNE
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_add_grant_permissions(capsys, db: Database, db_cleanup):
    existing_grant = (await db.get_grants())[0]  # default: view:permissions, edit:permissions

    r = await cli.main(["add-grant-permissions", str(existing_grant.id), str(P_QUERY_DATA), str(P_INGEST_DATA)])
    assert r == 0

    assert (await db.get_grant(existing_grant.id)).permissions == existing_grant.permissions.union(
        frozenset({P_QUERY_DATA, P_INGEST_DATA})
    )

    r = await cli.main(["add-grant-permissions", str(existing_grant.id), str(P_QUERY_DATA), str(P_INGEST_DATA)])
    assert r == 0
    captured = capsys.readouterr()
    assert captured.err.startswith(f"Grant {existing_grant.id} already has permissions")

    r = await cli.main(["add-grant-permissions", "0", str(P_QUERY_DATA), str(P_INGEST_DATA)])
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_set_grant_permissions(capsys, db: Database, db_cleanup):
    existing_grant = (await db.get_grants())[0]  # default: view:permissions, edit:permissions

    r = await cli.main(["set-grant-permissions", str(existing_grant.id), str(P_QUERY_DATA), str(P_INGEST_DATA)])
    assert r == 0

    assert (await db.get_grant(existing_grant.id)).permissions == frozenset({P_QUERY_DATA, P_INGEST_DATA})

    r = await cli.main(["set-grant-permissions", "0", str(P_QUERY_DATA), str(P_INGEST_DATA)])
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_delete_bad_entity(db: Database, db_cleanup):
    class Args:
        def __init__(self):
            self.entity = "abc"

    assert (await cli.delete_cmd(get_config(), db, object())) == 1
    assert (await cli.delete_cmd(get_config(), db, Args())) == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_delete_grant(capsys, db: Database, db_cleanup):
    assert len(await db.get_grants()) == 1

    existing_grant = (await db.get_grants())[0]

    r = await cli.main(["delete", "grant", str(existing_grant.id)], db=db)
    assert r == 0

    assert len(await db.get_grants()) == 0

    r = await cli.main(["delete", "grant", str(existing_grant.id)], db=db)  # Not found
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_delete_group(capsys, db_no: Database, db_cleanup_no):
    grp = sd.TEST_GROUPS[0][0]

    # Create a group
    g_id = await db_no.create_group(grp)

    # Delete the group
    assert (await cli.main(["delete", "group", str(g_id)], db=db_no)) == 0
    captured = capsys.readouterr()

    assert "Done" in captured.out


async def _check_only_grant_permissions(db: Database, asserted_permissions: frozenset[Permission]):
    grants = await db.get_grants()

    # There now should be one grant (whichever was created in the test calling this function)
    assert len(grants) == 1

    # The final set of permissions should match the specified set
    assert grants[0].permissions == asserted_permissions


def _check_grant_created(capsys):
    captured = capsys.readouterr()
    assert "Grant successfully created:" in captured.out


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_assign_all(capsys, db_no: Database, db_cleanup_no):
    # Assign all permissions to David
    assert (await cli.main(["assign-all-to-user", sd.SUBJECT_DAVID.root.iss, sd.SUBJECT_DAVID.root.sub])) == 0

    # The final set of permissions should have all of them:
    await _check_only_grant_permissions(db_no, frozenset(PERMISSIONS))


@pytest.mark.asyncio
async def test_cli_public_data_none(capsys, db_no: Database, db_cleanup_no):
    assert (await cli.main(["public-data-access", "none"])) == 0

    captured = capsys.readouterr()
    assert "Nothing to do" in captured.out

    # There should be no grants in the database:
    assert len(await db_no.get_grants()) == 0


@pytest.mark.asyncio
async def test_cli_public_data_bool(capsys, db_no: Database, db_cleanup_no):
    assert (await cli.main(["public-data-access", "bool"])) == 0
    _check_grant_created(capsys)

    # There should be 1 grant in the database, with boolean permissions only:
    await _check_only_grant_permissions(
        db_no, frozenset((P_QUERY_PROJECT_LEVEL_BOOLEAN, P_QUERY_DATASET_LEVEL_BOOLEAN))
    )


@pytest.mark.asyncio
async def test_cli_public_data_counts(capsys, db_no: Database, db_cleanup_no):
    assert (await cli.main(["public-data-access", "counts"])) == 0
    _check_grant_created(capsys)

    # There should be 1 grant in the database, with counts permissions:
    await _check_only_grant_permissions(db_no, frozenset((P_QUERY_PROJECT_LEVEL_COUNTS, P_QUERY_DATASET_LEVEL_COUNTS)))


QD_FS = frozenset((P_QUERY_DATA,))


@pytest.mark.asyncio
async def test_cli_public_data_full(capsys, monkeypatch, db_no: Database, db_cleanup_no):
    monkeypatch.setattr("sys.stdin", io.StringIO("y"))  # mock stdin with yes response

    assert (await cli.main(["public-data-access", "full"])) == 0
    _check_grant_created(capsys)

    # There should be 1 grant in the database, with full querying permissions:
    await _check_only_grant_permissions(db_no, QD_FS)


@pytest.mark.asyncio
async def test_cli_public_data_full_force(capsys, monkeypatch, db_no: Database, db_cleanup_no):
    assert (await cli.main(["public-data-access", "-f", "full"])) == 0
    _check_grant_created(capsys)

    # There should be 1 grant in the database, with full querying permissions:
    await _check_only_grant_permissions(db_no, QD_FS)


@pytest.mark.asyncio
async def test_cli_public_data_no(capsys, monkeypatch, db_no: Database, db_cleanup_no):
    monkeypatch.setattr("sys.stdin", io.StringIO("n"))  # mock stdin with no response

    assert (await cli.main(["public-data-access", "full"])) == 0

    captured = capsys.readouterr()
    assert "Exiting without doing anything." in captured.out

    # There should be no grants in the database:
    assert len(await db_no.get_grants()) == 0


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_help_works(capsys, db_no: Database, db_cleanup_no):
    with pytest.raises(SystemExit) as e:
        await cli.main(["--help"])
        assert e.value == "0"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_help_works_2(capsys, db_no: Database, db_cleanup_no):
    with pytest.raises(SystemExit) as e:
        await cli.main([])
        assert e.value == "0"
