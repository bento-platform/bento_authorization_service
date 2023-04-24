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
TEST_GRANT_CLIENT_PROJECT_1_QUERY_DATA: Grant = {
    "subject": SUBJECT_CLIENT,
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
