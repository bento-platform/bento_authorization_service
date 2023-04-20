import pytest
from bento_authorization_service.policy_engine.evaluation import (
    InvalidGrant,
    InvalidGroupMembership,
    InvalidResourceRequest,
    check_if_token_is_in_group,
    check_if_grant_subject_matches_token,
    check_if_grant_resource_matches_requested_resource,
    filter_matching_grants,
    determine_permissions,
)
from bento_authorization_service.policy_engine.permissions import P_QUERY_DATA
from bento_authorization_service.types import Subject, Resource, Grant, Group, GroupMembership


ISS = "https://bentov2auth.local/realms/bentov2"
CLIENT = "local_bentov2"
SUB = "david"

TEST_TOKEN = {
    "iss": ISS,
    "sub": SUB,
    "aud": "account",
    "azp": CLIENT,
    "typ": "Bearer",
    "exp": 100,  # Not checked here
    "iat": 0,  # Not checked here
}

TEST_TOKEN_NOT_DAVID = {
    "iss": ISS,
    "sub": "not_david",
    "aud": "account",
    "azp": CLIENT,
    "typ": "Bearer",
    "exp": 100,  # Not checked here
    "iat": 0,  # Not checked here
}

TEST_TOKEN_FOREIGN_ISS = {
    "iss": "https://google.com",
    "sub": SUB,
    "aud": "account",
    "azp": CLIENT,
    "typ": "Bearer",
    "exp": 100,  # Not checked here
    "iat": 0,  # Not checked here
}

SUBJECT_EVERYONE: Subject = {"everyone": True}
SUBJECT_CLIENT: Subject = {"iss": ISS, "client": CLIENT}
SUBJECT_DAVID: Subject = {"iss": ISS, "sub": SUB}
SUBJECT_NOT_ME: Subject = {"iss": ISS, "sub": "not_me"}

RESOURCE_EVERYTHING: Resource = {"everything": True}
RESOURCE_PROJECT_1: Resource = {"project": "1"}
RESOURCE_PROJECT_1_DATASET_A: Resource = {"project": "1", "dataset": "A"}
RESOURCE_PROJECT_1_DATASET_B: Resource = {"project": "1", "dataset": "B"}
RESOURCE_PROJECT_2: Resource = {"project": "2"}
RESOURCE_PROJECT_2_DATASET_C: Resource = {"project": "1", "dataset": "B"}

TEST_GROUP_MEMBERSHIPS: list[tuple[GroupMembership | None, bool]] = [
    # Member lists

    ({"members": [{"iss": ISS, "client": CLIENT}]}, True),  # All users from a particular issuer+client

    ({"members": [SUBJECT_DAVID]}, True),  # A specific user

    ({"members": [SUBJECT_NOT_ME]}, False),  # Not me!

    ({"members": [SUBJECT_DAVID, SUBJECT_NOT_ME]}, True),  # Me and not me!
    ({"members": [SUBJECT_NOT_ME, SUBJECT_DAVID]}, True),  # Me and not me!

    # Expressions

    ({
         "expr": ["#and", ["#eq", ["#resolve", "sub"], SUB], ["#eq", ["#resolve", "iss"], ISS]]
     }, True),  # Expression for specific subject and issuer
]
TEST_GROUPS: list[tuple[Group, bool]] = [
    ({"id": i, "membership": x}, r)
    for i, (x, r) in enumerate(TEST_GROUP_MEMBERSHIPS)
]
TEST_GROUPS_DICT: dict[int, Group] = {x["id"]: x for x, _ in TEST_GROUPS}


TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA: Grant = {
    "subject": SUBJECT_EVERYONE,
    "resource": RESOURCE_EVERYTHING,
    "permission": P_QUERY_DATA,
    "extra": {},
}
TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA: Grant = {
    "subject": SUBJECT_EVERYONE,
    "resource": RESOURCE_PROJECT_1,
    "permission": P_QUERY_DATA,
    "extra": {},
}
TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA: Grant = {
    "subject": {"group": 0},
    "resource": RESOURCE_PROJECT_1,
    "permission": P_QUERY_DATA,
    "extra": {},
}
TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA: Grant = {
    "subject": {"group": 0},
    "resource": RESOURCE_PROJECT_2,
    "permission": P_QUERY_DATA,
    "extra": {},
}
TEST_GRANT_GROUP_2_PROJECT_1_QUERY_DATA: Grant = {
    "subject": {"group": 2},
    "resource": RESOURCE_PROJECT_1,
    "permission": P_QUERY_DATA,
    "extra": {},
}
TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA: Grant = {
    "subject": SUBJECT_DAVID,
    "resource": RESOURCE_PROJECT_1,
    "permission": P_QUERY_DATA,
    "extra": {},
}


def test_invalid_group_membership():
    with pytest.raises(InvalidGroupMembership):
        check_if_token_is_in_group(TEST_TOKEN, {"id": 1000, "membership": {}})
    with pytest.raises(InvalidGroupMembership):  # Must not be a malformatted member
        check_if_token_is_in_group(TEST_TOKEN, {"id": 1000, "membership": {"members": [{"bad": True}]}})
    with pytest.raises(InvalidGroupMembership):  # Must specify client or subject
        check_if_token_is_in_group(TEST_TOKEN, {"id": 1000, "membership": {"members": [{"iss": ISS}]}})


@pytest.mark.parametrize("group, is_member", TEST_GROUPS)
def test_group_membership(group: Group, is_member: bool):
    assert not check_if_token_is_in_group(None, group)
    assert check_if_token_is_in_group(TEST_TOKEN, group) == is_member
    assert not check_if_token_is_in_group(TEST_TOKEN_FOREIGN_ISS, group)  # All groups have local issuer


def test_subject_match():
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)  # Everyone
    # Everyone (even foreign issuer):
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN_FOREIGN_ISS, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)
    # No token:
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, None, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)

    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN, TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)  # Everyone

    # Members of group 0 (iss/client-based):
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN, TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN_NOT_DAVID, TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)

    # NOT a member of group 2:
    assert not check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN, TEST_GRANT_GROUP_2_PROJECT_1_QUERY_DATA)

    # David:
    assert check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN, TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)

    # NOT David:
    assert not check_if_grant_subject_matches_token(
        TEST_GROUPS_DICT, TEST_TOKEN_NOT_DAVID, TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA)


def test_invalid_grants():
    # Missing group raise:
    with pytest.raises(InvalidGrant):
        # No groups defined
        check_if_grant_subject_matches_token({}, TEST_TOKEN, TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)


def test_resource_match():
    assert check_if_grant_resource_matches_requested_resource(
        RESOURCE_EVERYTHING, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)
    assert check_if_grant_resource_matches_requested_resource(
        RESOURCE_PROJECT_1_DATASET_A, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)  # Project 1 is a subset of everything

    # Permission applies to Project 1, but we are checking for Everything, so it should be False:
    assert not check_if_grant_resource_matches_requested_resource(
        RESOURCE_EVERYTHING, TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)

    # Same project, optionally requesting a specific dataset of the project
    assert check_if_grant_resource_matches_requested_resource(
        RESOURCE_PROJECT_1, TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)
    assert check_if_grant_resource_matches_requested_resource(
        RESOURCE_PROJECT_1_DATASET_A, TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA)


def test_invalid_resource_request():
    with pytest.raises(InvalidResourceRequest):
        check_if_grant_resource_matches_requested_resource({}, TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA)
    with pytest.raises(InvalidResourceRequest):
        check_if_grant_resource_matches_requested_resource({}, TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)


def test_grant_filtering_and_permissions_set():
    grants_1 = (TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA, TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA)
    args_1 = (grants_1, TEST_GROUPS_DICT, TEST_TOKEN, RESOURCE_PROJECT_1_DATASET_A)
    matching_token_1 = tuple(filter_matching_grants(*args_1))
    permissions_set_1 = determine_permissions(*args_1)
    assert len(matching_token_1) == 2  # Matches subject and resource on both
    assert permissions_set_1 == frozenset({P_QUERY_DATA})

    args_2 = ((TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA,), TEST_GROUPS_DICT, TEST_TOKEN, RESOURCE_PROJECT_1_DATASET_A)
    matching_token_1 = tuple(filter_matching_grants(*args_2))
    permissions_set_2 = determine_permissions(*args_2)
    assert len(matching_token_1) == 0  # Different project
    assert permissions_set_2 == frozenset()

    matching_token_2 = tuple(filter_matching_grants((
        TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA,
        TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
    ), TEST_GROUPS_DICT, TEST_TOKEN_FOREIGN_ISS, RESOURCE_PROJECT_1_DATASET_A))
    assert len(matching_token_2) == 1  # Everyone + everything applies, but not grant 2 (foreign issuer, not in group 0)

    matching_token_2 = tuple(filter_matching_grants((
        TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
    ), TEST_GROUPS_DICT, TEST_TOKEN_FOREIGN_ISS, RESOURCE_PROJECT_1_DATASET_A))
    assert len(matching_token_2) == 0  # Foreign issuer, not in group 0