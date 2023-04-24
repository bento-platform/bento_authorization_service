from fastapi import status
from fastapi.testclient import TestClient
import json
import pytest
from bento_authorization_service.db import Database
from bento_authorization_service.types import Group

from .shared_data import TEST_GROUPS


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


@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_creation(group: Group, _is_member: bool, test_client: TestClient, db: Database):
    # Group can be created via endpoint
    g = {**group}
    del g["id"]
    res = test_client.post("/groups/", json=g)
    assert res.status_code == status.HTTP_201_CREATED

    # Verify group exists in database
    g_rest = res.json()
    assert json.dumps(await db.get_group(g_rest["id"]), sort_keys=True) == json.dumps(g_rest, sort_keys=True)


def test_group_endpoints_fetch_404(test_client: TestClient):
    res = test_client.get("/groups/0")  # Below serial 1
    assert res.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_fetch(group: Group, _is_member: bool, test_client: TestClient, db: Database):
    # Create group in database directly
    g_db = await db.create_group(group)

    # Test that we can fetch the group via endpoint
    res = test_client.get(f"/groups/{g_db}")
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()
    assert json.dumps({**group, "id": g_db}, sort_keys=True) == json.dumps(res_data, sort_keys=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_list(group: Group, _is_member: bool, test_client: TestClient, db: Database):
    # Create group in database directly
    g_db = await db.create_group(group)

    # Test that we can find the group via list endpoint
    res = test_client.get(f"/groups/")
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()
    group_in_list = next((g for g in res_data if g["id"] == g_db), None)
    assert json.dumps({**group, "id": g_db}, sort_keys=True) == json.dumps(group_in_list, sort_keys=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_delete(group: Group, _is_member: bool, test_client: TestClient, db: Database):
    # Create group in database directly
    g_db = await db.create_group(group)

    # Test that we can delete the group
    res = test_client.delete(f"/groups/{g_db}")
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # Test that we can delete again - it is a 404, but not an internal error
    res = test_client.delete(f"/groups/{g_db}")
    assert res.status_code == status.HTTP_404_NOT_FOUND
