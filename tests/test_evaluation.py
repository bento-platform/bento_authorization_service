import jwt
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from bento_authorization_service.db import Database
from bento_authorization_service.idp_manager import IdPManager
from bento_authorization_service.policy_engine.evaluation import (
    InvalidGrant,
    InvalidGroupMembership,
    InvalidResourceRequest,
    check_if_token_is_in_group,
    check_if_grant_subject_matches_token,
    check_if_grant_resource_matches_requested_resource,
    filter_matching_grants,
    determine_permissions,
    evaluate,
)
from bento_authorization_service.policy_engine.permissions import P_QUERY_DATA
from bento_authorization_service.types import Grant, Group

from . import shared_data as sd


def test_invalid_group_membership():
    with pytest.raises(InvalidGroupMembership):
        check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {}})
    with pytest.raises(InvalidGroupMembership):  # Must not be a malformatted member
        check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {"members": [{"bad": True}]}})
    with pytest.raises(InvalidGroupMembership):  # Must specify client or subject
        check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {"members": [{"iss": sd.ISS}]}})


@pytest.mark.parametrize("group, is_member", sd.TEST_GROUPS)
def test_group_membership(group: Group, is_member: bool):
    assert not check_if_token_is_in_group(None, group)
    assert check_if_token_is_in_group(sd.TEST_TOKEN, group) == is_member
    assert not check_if_token_is_in_group(sd.TEST_TOKEN_FOREIGN_ISS, group)  # All groups have local issuer


def test_subject_match():
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)  # Everyone
    # Everyone (even foreign issuer):
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_FOREIGN_ISS, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)
    # No token:
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, None, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)

    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)  # Everyone

    # Members of group 0 (iss/client-based):
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_NOT_DAVID, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)

    # NOT a member of group 2:
    assert not check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_2_PROJECT_1_QUERY_DATA)

    # Client grant
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_CLIENT_PROJECT_1_QUERY_DATA)

    # David:
    assert check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)

    # NOT David:
    assert not check_if_grant_subject_matches_token(
        sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_NOT_DAVID, sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)


def test_invalid_grants():
    # Missing group raise:
    with pytest.raises(InvalidGrant):
        # No groups defined
        check_if_grant_subject_matches_token({}, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)


def test_resource_match():
    assert check_if_grant_resource_matches_requested_resource(
        sd.RESOURCE_EVERYTHING, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)

    # Project 1 is a subset of everything:
    assert check_if_grant_resource_matches_requested_resource(
        sd.RESOURCE_PROJECT_1_DATASET_A, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)

    # Permission applies to Project 1, but we are checking for Everything, so it should be False:
    assert not check_if_grant_resource_matches_requested_resource(
        sd.RESOURCE_EVERYTHING, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)

    # Same project, optionally requesting a specific dataset of the project
    assert check_if_grant_resource_matches_requested_resource(
        sd.RESOURCE_PROJECT_1, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)
    assert check_if_grant_resource_matches_requested_resource(
        sd.RESOURCE_PROJECT_1_DATASET_A, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)


def test_invalid_resource_request():
    with pytest.raises(InvalidResourceRequest):
        check_if_grant_resource_matches_requested_resource({}, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)
    with pytest.raises(InvalidResourceRequest):
        check_if_grant_resource_matches_requested_resource({}, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)


def test_grant_filtering_and_permissions_set():
    grants_1 = (sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)
    args_1 = (grants_1, sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.RESOURCE_PROJECT_1_DATASET_A)
    matching_token_1 = tuple(filter_matching_grants(*args_1))
    permissions_set_1 = determine_permissions(*args_1)
    assert len(matching_token_1) == 2  # Matches subject and resource on both
    assert permissions_set_1 == frozenset({P_QUERY_DATA})

    args_2 = ((sd.TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA,), sd.TEST_GROUPS_DICT, sd.TEST_TOKEN,
              sd.RESOURCE_PROJECT_1_DATASET_A)
    matching_token_1 = tuple(filter_matching_grants(*args_2))
    permissions_set_2 = determine_permissions(*args_2)
    assert len(matching_token_1) == 0  # Different project
    assert permissions_set_2 == frozenset()

    matching_token_2 = tuple(filter_matching_grants((
        sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA,
        sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
    ), sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_FOREIGN_ISS, sd.RESOURCE_PROJECT_1_DATASET_A))
    assert len(matching_token_2) == 1  # Everyone + everything applies, but not grant 2 (foreign issuer, not in group 0)

    matching_token_2 = tuple(filter_matching_grants((
        sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
    ), sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_FOREIGN_ISS, sd.RESOURCE_PROJECT_1_DATASET_A))
    assert len(matching_token_2) == 0  # Foreign issuer, not in group 0


async def _eval_test_data(db: Database):
    group_id = await db.create_group(sd.TEST_GROUPS[0][0])
    grant_with_group = {**sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA, "subject": {"group": group_id}}
    await db.create_grant(Grant(**grant_with_group))
    ts = int(datetime.utcnow().timestamp())
    tkn = jwt.encode({**sd.TEST_TOKEN, "iat": ts, "exp": ts + 900}, "secret", algorithm="HS256")
    return tkn


@pytest.mark.asyncio
async def test_evaluate_function(db: Database, idp_manager: IdPManager, test_client: TestClient):
    tkn = await _eval_test_data(db)
    res = await evaluate(idp_manager, db, tkn, sd.RESOURCE_PROJECT_1, frozenset({P_QUERY_DATA}))
    assert res


@pytest.mark.asyncio
async def test_evaluate_endpoint(db: Database, test_client: TestClient):
    tkn = await _eval_test_data(db)
    res = test_client.post("/policy/evaluate", headers={"Authorization": f"Bearer {tkn}"}, json={
        "requested_resource": sd.RESOURCE_PROJECT_1,
        "required_permissions": [str(P_QUERY_DATA)],
    })
    assert res.json()["result"]
