from fastapi import status
from fastapi.testclient import TestClient
import json
import pytest
from bento_authorization_service.db import Database
from bento_authorization_service.models import GroupModel, StoredGroupModel

from .shared_data import TEST_GROUPS


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_db_group(db: Database, db_cleanup):
    g = TEST_GROUPS[0][0]

    g_id: int = await db.create_group(TEST_GROUPS[0][0])
    g_db: StoredGroupModel = await db.get_group(g_id)

    # IDs won't be the same necessarily, so compare based on membership
    assert json.dumps(g.membership.dict(), sort_keys=True) == json.dumps(g_db.membership.dict(), sort_keys=True)

    groups_list = await db.get_groups()
    groups_dict = await db.get_groups_dict()

    # We should have the group in the list too!
    assert any(gg.id == g_db.id for gg in groups_list)
    # .. and in the dict!
    assert g_db.id in groups_dict

    # And the groups list/dict should be the same length.
    assert len(groups_list) == len(groups_dict)

    # Update membership: just David
    # noinspection PyTypeChecker
    await db.set_group(g_id, GroupModel(**{**g.dict(), "membership": TEST_GROUPS[1][0].membership}))
    g_db = await db.get_group(g_id)
    assert json.dumps(g_db.membership.dict(), sort_keys=True) == json.dumps(
        TEST_GROUPS[1][0].membership.dict(), sort_keys=True)

    # Now check we can delete the group successfully
    await db.delete_group_and_dependent_grants(g_db.id)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_db_group_non_existant(db: Database, db_cleanup):
    assert (await db.get_group(-1)) is None


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_creation(group: GroupModel, _is_member: bool, test_client: TestClient, db: Database,
                                        db_cleanup):
    # Group can be created via endpoint
    g = json.loads(group.json())
    del g["id"]
    res = test_client.post("/groups/", json=g)
    assert res.status_code == status.HTTP_201_CREATED

    # Verify group exists in database
    g_rest = res.json()
    group_from_db = await db.get_group(g_rest["id"])
    assert group_from_db is not None
    group_from_db_dict = json.loads(group_from_db.json())

    assert json.dumps(group_from_db_dict, sort_keys=True) == json.dumps(g_rest, sort_keys=True)


# noinspection PyUnusedLocal
def test_group_endpoints_fetch_404(test_client: TestClient, db_cleanup):
    res = test_client.get("/groups/0")  # Below serial 1
    assert res.status_code == status.HTTP_404_NOT_FOUND


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_fetch(group: GroupModel, _is_member: bool, test_client: TestClient, db: Database,
                                     db_cleanup):
    # Create group in database directly
    g_db_id = await db.create_group(group)

    # Test that we can fetch the group via endpoint
    res = test_client.get(f"/groups/{g_db_id}")
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()

    assert "created" in res_data
    group_dict = {**json.loads(group.json()), "created": res_data["created"], "id": g_db_id}

    assert json.dumps(group_dict, sort_keys=True) == json.dumps(res_data, sort_keys=True)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_list(group: GroupModel, _is_member: bool, test_client: TestClient, db: Database,
                                    db_cleanup):
    # Create group in database directly
    g_db_id = await db.create_group(group)

    # Test that we can find the group via list endpoint
    res = test_client.get(f"/groups/")
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()
    group_in_list = next((g for g in res_data if g["id"] == g_db_id), None)

    assert "created" in group_in_list

    # Steal create date from created group for equality check
    group_dict = {**json.loads(group.json()), "created": group_in_list["created"], "id": g_db_id}

    # TODO: pydantic 2: group.model_dump(mode='json')
    assert json.dumps(group_dict, sort_keys=True) == json.dumps(group_in_list, sort_keys=True)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_delete(group: GroupModel, _is_member: bool, test_client: TestClient, db: Database,
                                      db_cleanup):
    # Create group in database directly
    g_db = await db.create_group(group)

    # Test that we can delete the group
    res = test_client.delete(f"/groups/{g_db}")
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # Test that we can delete again - it is a 404, but not an internal error
    res = test_client.delete(f"/groups/{g_db}")
    assert res.status_code == status.HTTP_404_NOT_FOUND
