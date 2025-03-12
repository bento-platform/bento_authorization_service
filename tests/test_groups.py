from fastapi import status
from fastapi.testclient import TestClient
import json
import pytest
from bento_authorization_service.db import Database
from bento_authorization_service.models import GroupModel, StoredGroupModel

from .shared_data import TEST_GROUPS, TEST_EXPIRED_GROUP
from .utils import compare_via_json, compare_model_json


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_db_group(db: Database, db_cleanup):
    g = TEST_GROUPS[0][0]

    g_id: int = await db.create_group(TEST_GROUPS[0][0])
    g_db: StoredGroupModel = await db.get_group(g_id)

    # IDs won't be the same necessarily, so compare based on membership
    assert json.dumps(
        g.membership.model_dump(mode="json"),
        sort_keys=True,
    ) == json.dumps(g_db.membership.model_dump(mode="json"), sort_keys=True)

    groups_list = await db.get_groups()
    groups_dict = await db.get_groups_dict()

    # We should have the group in the list too!
    assert any(gg.id == g_db.id for gg in groups_list)
    # ... and in the dict!
    assert g_db.id in groups_dict

    # And the groups list/dict should be the same length.
    assert len(groups_list) == len(groups_dict)

    # Update membership: just David
    # noinspection PyTypeChecker
    await db.set_group(g_id, GroupModel(**{**g.model_dump(), "membership": TEST_GROUPS[1][0].membership}))
    g_db = await db.get_group(g_id)
    assert compare_model_json(g_db.membership, TEST_GROUPS[1][0].membership)

    # Now check we can delete the group successfully
    await db.delete_group_and_dependent_grants(g_db.id)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_db_group_non_existant(db: Database, db_cleanup):
    assert (await db.get_group(-1)) is None


# noinspection PyUnusedLocal
def test_expired_group_creation_error(auth_headers: dict[str, str], test_client: TestClient, db_cleanup):
    res = test_client.post("/groups/", json=TEST_EXPIRED_GROUP.model_dump(mode="json"), headers=auth_headers)
    assert res.status_code == status.HTTP_400_BAD_REQUEST


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_creation(
    group: GroupModel, _is_member: bool, auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup
):
    g = group.model_dump(mode="json")
    del g["id"]

    # Group cannot be created without token
    res = test_client.post("/groups/", json=g)
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Group can be created via endpoint
    res = test_client.post("/groups/", json=g, headers=auth_headers)
    assert res.status_code == status.HTTP_201_CREATED

    # Verify group exists in database
    g_rest = res.json()
    group_from_db = await db.get_group(g_rest["id"])
    assert group_from_db is not None
    assert compare_via_json(group_from_db.model_dump(mode="json"), g_rest)


# noinspection PyUnusedLocal
def test_group_endpoints_fetch_404(auth_headers: dict[str, str], test_client: TestClient, db_cleanup):
    # No authz, can't tell if we have this group or not
    res = test_client.get("/groups/0")  # Below serial 1
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Authz, confirm we don't have it
    res = test_client.get("/groups/0", headers=auth_headers)  # Below serial 1
    assert res.status_code == status.HTTP_404_NOT_FOUND


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_fetch(
    group: GroupModel, _is_member: bool, auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup
):
    # Create group in database directly
    g_db_id = await db.create_group(group)

    # Test that we cannot get the group without auth headers
    res = test_client.get(f"/groups/{g_db_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Test that we can fetch the group via endpoint
    res = test_client.get(f"/groups/{g_db_id}", headers=auth_headers)
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()

    assert "created" in res_data
    group_dict = {**group.model_dump(mode="json"), "created": res_data["created"], "id": g_db_id}
    assert compare_via_json(group_dict, res_data)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_list(
    group: GroupModel, _is_member: bool, auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup
):
    # Create group in database directly
    g_db_id = await db.create_group(group)

    # Test that we cannot list groups without authorization
    res = test_client.get("/groups/")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Test that we can find the group via list endpoint
    res = test_client.get("/groups/", headers=auth_headers)
    assert res.status_code == status.HTTP_200_OK
    res_data = res.json()
    group_in_list = next((g for g in res_data if g["id"] == g_db_id), None)

    assert "created" in group_in_list

    # Steal create date from created group for equality check
    group_dict = {**group.model_dump(mode="json"), "created": group_in_list["created"], "id": g_db_id}
    assert compare_via_json(group_dict, group_in_list)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
@pytest.mark.parametrize("group, _is_member", TEST_GROUPS)
async def test_group_endpoints_delete(
    group: GroupModel, _is_member: bool, auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup
):
    # Create group in database directly
    g_db_id = await db.create_group(group)

    # Test that we cannot delete groups without authorization
    res = test_client.get(f"/groups/{g_db_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Test that we can delete the group
    res = test_client.delete(f"/groups/{g_db_id}", headers=auth_headers)
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # Test that we can delete again - it is a 404, but not an internal error
    res = test_client.delete(f"/groups/{g_db_id}", headers=auth_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_group_endpoints_update(auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup):
    group_1 = TEST_GROUPS[0][0]
    group_2 = TEST_GROUPS[1][0]

    # Create group in database directly
    g_db_id = await db.create_group(group_1)

    # Check it matches the first one
    g_db = await db.get_group(g_db_id)
    assert g_db is not None and compare_model_json(g_db, group_1, exclude={"id", "created"})

    # Test we cannot update with no authorization
    res = test_client.put(f"/groups/{g_db_id}", json=group_2.model_dump(mode="json"))
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Test we can make an update request
    res = test_client.put(f"/groups/{g_db_id}", json=group_2.model_dump(mode="json"), headers=auth_headers)
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # Check it now matches the second one
    g_db = await db.get_group(g_db_id)
    assert g_db is not None and compare_model_json(g_db, group_2, exclude={"id", "created"})

    # Check idempotency
    res = test_client.put(f"/groups/{g_db_id}", json=group_2.model_dump(mode="json"), headers=auth_headers)
    assert res.status_code == status.HTTP_204_NO_CONTENT
    g_db = await db.get_group(g_db_id)
    assert g_db is not None and compare_model_json(g_db, group_2, exclude={"id", "created"})

    # Check it 404s for a not-found group with auth

    res = test_client.put("/groups/0", json=group_2.model_dump(mode="json"))
    assert res.status_code == status.HTTP_403_FORBIDDEN

    res = test_client.put("/groups/0", json=group_2.model_dump(mode="json"), headers=auth_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND
