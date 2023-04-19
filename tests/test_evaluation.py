import pytest
from bento_authorization_service.policy_engine.evaluation import check_if_token_is_in_group
from bento_authorization_service.types import Group, GroupMembership


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

TEST_GROUP_MEMBERSHIPS: list[tuple[GroupMembership | None, bool]] = [
    # Member lists

    ({"members": [{"iss": ISS, "client": CLIENT}]}, True),  # All users from a particular issuer+client

    ({"members": [{"iss": ISS, "sub": SUB}]}, True),  # A specific user

    ({"members": [{"iss": ISS, "sub": "not_me"}]}, False),  # Not me!

    ({"members": [{"iss": ISS, "sub": SUB}, {"iss": ISS, "sub": "not_me"}]}, True),  # Me and not me!
    ({"members": [{"iss": ISS, "sub": "not_me"}, {"iss": ISS, "sub": SUB}]}, True),  # Me and not me!

    # Expressions

    ({
         "expr": ["#and", ["#eq", ["#resolve", "sub"], SUB], ["#eq", ["#resolve", "iss"], ISS]]
     }, True),  # Expression for specific subject and issuer
]
TEST_GROUPS: list[tuple[Group, bool]] = [
    ({"id": i, "membership": x}, r)
    for i, (x, r) in enumerate(TEST_GROUP_MEMBERSHIPS)
]


@pytest.mark.parametrize("group, is_member", TEST_GROUPS)
def test_group_membership(group: Group, is_member: bool):
    assert check_if_token_is_in_group(None, group) == False
    assert check_if_token_is_in_group(TEST_TOKEN, group) == is_member
