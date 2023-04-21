import json
import pytest
from bento_authorization_service.db import DatabaseError, Database
from bento_authorization_service.types import Group

from .shared_data import TEST_GROUPS


@pytest.mark.asyncio
async def test_db_close(db: Database):
    await db.close()
    assert db._pool is None

    # duplicate request: should be idempotent
    await db.close()
    assert db._pool is None

    # should not be able to connect
    with pytest.raises(DatabaseError):
        async with db.connect():
            pass


@pytest.mark.asyncio
async def test_db_group(db: Database):
    g: Group = Group(**TEST_GROUPS[0][0])
    g_id: int = await db.create_group(g)
    g_db: Group = await db.get_group(g_id)

    # IDs won't be the same necessarily, so compare based on membership
    assert json.dumps(g["membership"], sort_keys=True) == json.dumps(g_db["membership"], sort_keys=True)

    groups_list = await db.get_groups()
    groups_dict = await db.get_groups_dict()

    # We should have the group in the list too!
    assert any(gg["id"] == g_db["id"] for gg in groups_list)
    # .. and in the dict!
    assert g_db["id"] in groups_dict

    # And the groups list/dict should be the same length.
    assert len(groups_list) == len(groups_dict)

    # Update membership: just David
    await db.set_group({"id": g_id, "membership": TEST_GROUPS[1][0]["membership"]})
    g_db = await db.get_group(g_id)
    assert json.dumps(g_db["membership"], sort_keys=True) == json.dumps(TEST_GROUPS[1][0]["membership"], sort_keys=True)

    # Now check we can delete the group successfully
    await db.delete_group_and_dependent_grants(g_db["id"])


@pytest.mark.asyncio
async def test_db_group_non_existant(db: Database):
    assert (await db.get_group(-1)) is None
