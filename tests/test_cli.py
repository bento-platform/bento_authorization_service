import pytest
from bento_authorization_service.cli import main
from bento_authorization_service.db import Database
from bento_authorization_service.policy_engine.permissions import PERMISSIONS

from .shared_data import TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_permissions(capsys, db: Database, db_cleanup):
    await main(["list-permissions"], db=db)
    captured = capsys.readouterr()
    assert captured.out == "\n".join(PERMISSIONS) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_grants(capsys, db: Database, db_cleanup):
    await main(["list-grants"], db=db)
    captured = capsys.readouterr()

    # Default grant set for testing purposes:
    assert captured.out == "\n".join(map(lambda x: x.json(sort_keys=True), await db.get_grants())) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_create_grant(capsys, db: Database, db_cleanup):
    r = await main(
        [
            "create-grant",
            TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.subject.json(),
            TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.resource.json(),
            *TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.permissions,
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

    r = await main(["get-grant", str(existing_grant.id)], db=db)
    assert r == 0
    captured = capsys.readouterr()
    assert captured.out == existing_grant.json(sort_keys=True, indent=2) + "\n"

    r = await main(["get-grant", "-1"])  # DNE
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_delete_grant(capsys, db: Database, db_cleanup):
    assert len(await db.get_grants()) == 1

    existing_grant = (await db.get_grants())[0]

    r = await main(["delete-grant", str(existing_grant.id)], db=db)
    assert r == 0

    assert len(await db.get_grants()) == 0

    r = await main(["delete-grant", str(existing_grant.id)], db=db)  # Not found
    assert r == 1


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_help_works(capsys, db: Database, db_cleanup):
    with pytest.raises(SystemExit) as e:
        await main(["--help"])
        assert e.value == "0"

    with pytest.raises(SystemExit) as e:
        await main([])
        assert e.value == "0"
