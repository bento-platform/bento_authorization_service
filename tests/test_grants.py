import json
import pytest

from fastapi import status
from fastapi.testclient import TestClient
from pydantic import ValidationError

from bento_authorization_service.db import Database
from bento_authorization_service.models import GrantModel, StoredGrantModel
# from bento_authorization_service.policy_engine.evaluation import (
#     InvalidGrant,
#     check_if_grant_subject_matches_token,
#     check_if_grant_resource_matches_requested_resource,
# )

from . import shared_data as sd


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
    assert sd.SUBJECT_DAVID.json(sort_keys=True) == sub_db.json(sort_keys=True)


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
    assert sd.RESOURCE_PROJECT_1_DATASET_A.json(sort_keys=True) == res_db.json(sort_keys=True)


def test_bad_grant_subject():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.dict(), "subject": {}})

    # TODO: NotImplementedError tests
    # with pytest.raises(InvalidGrant):
    #     check_if_grant_subject_matches_token(sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, bad_grant)

    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.dict(), "subject": {"iss": sd.ISS}})

    # TODO: NotImplementedError tests
    # with pytest.raises(InvalidGrant):
    #     check_if_grant_subject_matches_token(sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, bad_grant)


def test_bad_grant_resource():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.dict(), "resource": {}})
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.dict(), "resource": ""})


def test_bad_grant_permission_length():
    with pytest.raises(ValidationError):
        GrantModel(**{**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.dict(), "permissions": frozenset()})


def test_not_implemented_grant_resource():
    # TODO - check if we define a new resource type we get NotImplementedError
    pass
    # with pytest.raises(InvalidGrant):
    #     check_if_grant_resource_matches_requested_resource(sd.RESOURCE_PROJECT_1, bad_grant)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_create(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    json_grant = {
        **json.loads(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.json()),
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
    assert json.dumps(res_data, sort_keys=True) == db_grant.json(sort_keys=True)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_create_expired(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}
    json_grant = json.loads(sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA_EXPIRED.json())

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
    g_id, _ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: StoredGrantModel = await db.get_grant(g_id)
    db_grant_json = db_grant.json(sort_keys=True)

    # test that without a token, we cannot see anything
    res = test_client.get(f"/grants/{g_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can fetch it
    res = test_client.get(f"/grants/{g_id}", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert json.dumps(res.json(), sort_keys=True) == db_grant_json


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_list(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # create grant in database
    g_id, _ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: StoredGrantModel = await db.get_grant(g_id)
    db_grant_json = db_grant.json(sort_keys=True)

    # test that without a token, we cannot see anything
    #  TODO
    # res = test_client.get("/grants/")
    # assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can find it in the list
    res = test_client.get("/grants/", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert any(True for g in res.json() if json.dumps(g, sort_keys=True) == db_grant_json)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_delete(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # create grant in database
    g_id, _ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)

    # test that without a token, we cannot delete it
    res = test_client.delete(f"/grants/{g_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can delete it
    res = test_client.delete(f"/grants/{g_id}", headers=headers)
    assert res.status_code == status.HTTP_204_NO_CONTENT

    # test that we can delete it again (but get 404)
    res = test_client.delete(f"/grants/{g_id}", headers=headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND
