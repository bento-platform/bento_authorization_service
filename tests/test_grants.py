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


@pytest.mark.asyncio
async def test_grant_endpoints_create(db: Database, test_client: TestClient):
    json_grant = {
        **sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA,
        "permission": str(sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA["permission"]),
    }
    res = test_client.post("/grants/", json=json_grant)
    assert res.status_code == status.HTTP_201_CREATED
    res_data = res.json()
    db_grant: dict = await db.get_grant(res_data["id"])
    if db_grant:
        db_grant["permission"] = str(db_grant["permission"])
    assert json.dumps(res_data, sort_keys=True) == json.dumps(db_grant, sort_keys=True)
