import json
import pytest

from bento_lib.auth import permissions
from fastapi import status
from fastapi.testclient import TestClient
from pydantic import ValidationError

from bento_authorization_service.db import Database
from bento_authorization_service.models import GrantModel, StoredGrantModel

from . import shared_data as sd
from .utils import compare_via_json, compare_model_json


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_subject_creation(db: Database, db_cleanup):
    sub_id = await db.create_subject_or_get_id(sd.SUBJECT_DAVID)
    assert sub_id is not None

    # Test recreation returns the same ID
    assert sub_id == await db.create_subject_or_get_id(sd.SUBJECT_DAVID)

    # Test that we can get the subject
    sub_db = await db.get_subject(sub_id)
    assert sub_db is not None
    assert compare_model_json(sd.SUBJECT_DAVID, sub_db)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_resource_creation(db: Database, db_cleanup):
    res_id = await db.create_resource_or_get_id(sd.RESOURCE_PROJECT_1_DATASET_A)
    assert res_id is not None

    # Test recreation returns the same ID
    assert res_id == await db.create_resource_or_get_id(sd.RESOURCE_PROJECT_1_DATASET_A)

    # Test that we can get the resource
    res_db = await db.get_resource(res_id)
    assert res_db is not None
    assert compare_model_json(sd.RESOURCE_PROJECT_1_DATASET_A, res_db)


def test_bad_grant_subject():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(), "subject": {}})

    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(), "subject": {"iss": sd.ISS}})


def test_bad_grant_resource():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(), "resource": {}})
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(), "resource": ""})


def test_bad_grant_permission_length():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(), "permissions": frozenset()})


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_create(db: Database, db_cleanup):
    id_ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    assert (await db.get_grant(id_)) is not None


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_add_permissions(db: Database, db_cleanup):
    id_ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    assert (await db.get_grant(id_)).permissions == frozenset({permissions.P_QUERY_DATA})

    await db.add_grant_permissions(id_, frozenset({permissions.P_EDIT_PERMISSIONS, permissions.P_INGEST_DATA}))
    assert (await db.get_grant(id_)).permissions == frozenset(
        {permissions.P_QUERY_DATA, permissions.P_EDIT_PERMISSIONS, permissions.P_INGEST_DATA}
    )


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_set_permissions(db: Database, db_cleanup):
    id_ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    assert (await db.get_grant(id_)).permissions == frozenset({permissions.P_QUERY_DATA})

    await db.set_grant_permissions(id_, frozenset({permissions.P_EDIT_PERMISSIONS, permissions.P_INGEST_DATA}))
    assert (await db.get_grant(id_)).permissions == frozenset(
        {permissions.P_EDIT_PERMISSIONS, permissions.P_INGEST_DATA}
    )


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_create(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    json_grant = {
        **sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.model_dump(mode="json"),
        "permissions": list(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.permissions),
    }

    # no token - forbidden
    res = test_client.post("/grants/", json=json_grant)
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # yes token - created
    res = test_client.post("/grants/", json=json_grant, headers=headers)
    assert res.status_code == status.HTTP_201_CREATED

    res_data = res.json()

    db_grant: StoredGrantModel = await db.get_grant(res_data["id"])
    assert compare_via_json(res_data, db_grant.model_dump(mode="json"))


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_create_expired(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}
    json_grant = sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA_EXPIRED.model_dump(mode="json")

    # not valid - expired
    res = test_client.post("/grants/", json=json_grant, headers=headers)
    assert res.status_code == status.HTTP_400_BAD_REQUEST


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_get(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # 404
    res = test_client.get("/grants/0", headers=headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND

    # create grant in database
    g_id = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: StoredGrantModel = await db.get_grant(g_id)

    # test that without a token, we cannot see anything
    res = test_client.get(f"/grants/{g_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can fetch it
    res = test_client.get(f"/grants/{g_id}", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert compare_via_json(db_grant.model_dump(mode="json"), res.json())


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_list(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # create grant in database
    g_id = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: StoredGrantModel = await db.get_grant(g_id)
    db_grant_json = json.dumps(db_grant.model_dump(mode="json"), sort_keys=True)

    # test that without a token, we cannot see anything
    res = test_client.get("/grants/")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can find it in the list
    res = test_client.get("/grants/", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert any(True for g in res.json() if json.dumps(g, sort_keys=True) == db_grant_json)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_delete(auth_headers: dict[str, str], test_client: TestClient, db: Database, db_cleanup):
    # create grant in database
    g_id = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)

    # test that without a token, we cannot delete it
    res = test_client.delete(f"/grants/{g_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can delete it
    res = test_client.delete(f"/grants/{g_id}", headers=auth_headers)
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # test that we can delete it again (but get 404)
    res = test_client.delete(f"/grants/{g_id}", headers=auth_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND
