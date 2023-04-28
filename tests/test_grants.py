import json
import pytest

from fastapi import status
from fastapi.testclient import TestClient

from bento_authorization_service.db import Database
from bento_authorization_service.policy_engine.evaluation import (
    InvalidGrant,
    check_if_grant_subject_matches_token,
    check_if_grant_resource_matches_requested_resource,
)
from bento_authorization_service.types import Grant

from . import shared_data as sd


def test_bad_grant_subject():
    # noinspection PyTypeChecker
    bad_grant: Grant = {**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA, "subject": {}}
    with pytest.raises(InvalidGrant):
        check_if_grant_subject_matches_token(sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, bad_grant)

    # noinspection PyTypeChecker
    bad_grant: Grant = {**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA, "subject": {"iss": sd.ISS}}
    with pytest.raises(InvalidGrant):
        check_if_grant_subject_matches_token(sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, bad_grant)


def test_bad_grant_resource():
    # noinspection PyTypeChecker
    bad_grant: Grant = {**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA, "resource": {}}
    with pytest.raises(InvalidGrant):
        check_if_grant_resource_matches_requested_resource(sd.RESOURCE_PROJECT_1, bad_grant)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_create(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    json_grant = {
        **sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA,
        "permission": str(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA["permission"]),
    }

    # no token - forbidden
    res = test_client.post("/grants/", json=json_grant)
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # yes token - created
    res = test_client.post("/grants/", json=json_grant, headers=headers)
    assert res.status_code == status.HTTP_201_CREATED

    res_data = res.json()

    db_grant: dict = await db.get_grant(res_data["id"])
    if db_grant:
        db_grant["permission"] = str(db_grant["permission"])

    assert json.dumps(res_data, sort_keys=True) == json.dumps(db_grant, sort_keys=True)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_get(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # 404
    res = test_client.get("/grants/0", headers=headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND

    # create grant in database
    g_id, _ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: dict = await db.get_grant(g_id)
    if db_grant:
        db_grant["permission"] = str(db_grant["permission"])

    # test that without a token, we cannot see anything
    res = test_client.get(f"/grants/{g_id}")
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can fetch it
    res = test_client.get(f"/grants/{g_id}", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert json.dumps(res.json(), sort_keys=True) == json.dumps(db_grant, sort_keys=True)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_grant_endpoints_list(test_client: TestClient, db: Database, db_cleanup):
    headers = {"Authorization": f"Bearer {sd.make_fresh_david_token_encoded()}"}

    # create grant in database
    g_id, _ = await db.create_grant(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)
    db_grant: dict = await db.get_grant(g_id)
    if db_grant:
        db_grant["permission"] = str(db_grant["permission"])

    # test that without a token, we cannot see anything
    #  TODO
    # res = test_client.get("/grants/")
    # assert res.status_code == status.HTTP_403_FORBIDDEN

    # test that we can find it in the list
    res = test_client.get("/grants/", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    assert any(True for g in res.json() if json.dumps(g, sort_keys=True) == json.dumps(db_grant, sort_keys=True))


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
