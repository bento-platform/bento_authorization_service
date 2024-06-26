import jwt

from bento_lib.auth.permissions import P_QUERY_DATA, P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS
from datetime import datetime, timedelta, timezone

from bento_authorization_service.db import Database
from bento_authorization_service.models import (
    IssuerAndSubjectModel,
    ResourceModel,
    SubjectModel,
    GroupMembershipExpr,
    GroupMembershipMembers,
    GroupMembership,
    GroupModel,
    StoredGroupModel,
    GrantModel,
)


TEST_TOKEN_SECRET = "secret"  # hard-coded test secret
TEST_TOKEN_AUD = "account"
TEST_TOKEN_SIGNING_ALG = "HS512"

ISS = "https://bentov2auth.local/realms/bentov2"
CLIENT = "local_bentov2"
SUB = "david"

TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS = frozenset(
    [  # only HS* for testing purposes
        "HS256",
        "HS384",
        TEST_TOKEN_SIGNING_ALG,
    ]
)

TEST_DISABLED_TOKEN_SIGNING_ALGOS = [  # disable all supported algos except the strongest one
    alg for alg in TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS if alg != TEST_TOKEN_SIGNING_ALG
]

TEST_TOKEN = {
    "iss": ISS,
    "sub": SUB,
    "aud": TEST_TOKEN_AUD,
    "azp": CLIENT,
    "typ": "Bearer",
    "exp": 100,  # Not checked here
    "iat": 0,  # Not checked here
}


def make_fresh_david_token(audience: str = TEST_TOKEN_AUD, exp_offset: int = 900):
    dt = int(datetime.now(timezone.utc).timestamp())
    return {**TEST_TOKEN, "aud": audience, "iat": dt, "exp": dt + exp_offset}


def make_fresh_david_token_encoded(**kwargs) -> str:
    return jwt.encode(make_fresh_david_token(**kwargs), TEST_TOKEN_SECRET, TEST_TOKEN_SIGNING_ALG)


def make_fresh_non_david_token_encoded(**kwargs) -> str:
    return jwt.encode({**make_fresh_david_token(**kwargs), "sub": "other"}, TEST_TOKEN_SECRET, TEST_TOKEN_SIGNING_ALG)


def make_fresh_david_disabled_alg_encoded() -> str:
    return jwt.encode(make_fresh_david_token(), TEST_TOKEN_SECRET, TEST_DISABLED_TOKEN_SIGNING_ALGOS[0])


async def bootstrap_meta_permissions_for_david(db: Database) -> None:
    # bootstrap create a permission for managing permissions
    await db.create_grant(SPECIAL_GRANT_DAVID_EVERYTHING_VIEW_EDIT_PERMISSIONS)


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

SUBJECT_EVERYONE: SubjectModel = SubjectModel({"everyone": True})
SUBJECT_CLIENT: SubjectModel = SubjectModel({"iss": ISS, "client": CLIENT})
SUBJECT_DAVID: SubjectModel = SubjectModel({"iss": ISS, "sub": SUB})
SUBJECT_NOT_ME: SubjectModel = SubjectModel({"iss": ISS, "sub": "not_me"})

RESOURCE_EVERYTHING: ResourceModel = ResourceModel({"everything": True})
RESOURCE_PROJECT_1: ResourceModel = ResourceModel({"project": "1"})
RESOURCE_PROJECT_1_DATASET_A: ResourceModel = ResourceModel({"project": "1", "dataset": "A"})
RESOURCE_PROJECT_1_DATASET_B: ResourceModel = ResourceModel({"project": "1", "dataset": "B"})
RESOURCE_PROJECT_2: ResourceModel = ResourceModel({"project": "2"})
RESOURCE_PROJECT_2_DATASET_C: ResourceModel = ResourceModel({"project": "1", "dataset": "B"})
RESOURCE_PROJECT_1_PHENOPACKET: ResourceModel = ResourceModel({"project": "1", "data_type": "phenopacket"})

TEST_GROUP_MEMBERSHIPS: list[tuple[GroupMembership, bool]] = [
    # Member lists
    # - All users from a particular issuer+client
    (GroupMembershipMembers(members=[{"iss": ISS, "client": CLIENT}]), True),
    # - A specific user
    (GroupMembershipMembers(members=[SUBJECT_DAVID.root]), True),
    # - Not me!
    (GroupMembershipMembers(members=[SUBJECT_NOT_ME.root]), False),
    # - Me and not me!
    (GroupMembershipMembers(members=[SUBJECT_DAVID.root, SUBJECT_NOT_ME.root]), True),
    # - Me and not me!
    (GroupMembershipMembers(members=[SUBJECT_NOT_ME.root, SUBJECT_DAVID.root]), True),
    # Expressions
    # - Expression for specific subject and issuer
    (GroupMembershipExpr(expr=["#and", ["#eq", ["#resolve", "sub"], SUB], ["#eq", ["#resolve", "iss"], ISS]]), True),
]
TEST_GROUP_CREATED: datetime = datetime.fromisoformat("2023-05-01T17:20:40.000000")
TEST_GROUPS: list[tuple[StoredGroupModel, bool]] = [
    (
        StoredGroupModel(
            **{
                "id": i,
                "name": f"group{i}",
                "membership": x,
                "created": TEST_GROUP_CREATED,
                "expiry": None,
            }
        ),
        r,
    )
    for i, (x, r) in enumerate(TEST_GROUP_MEMBERSHIPS)
]
TEST_GROUPS_DICT: dict[int, StoredGroupModel] = {x.id: x for x, _ in TEST_GROUPS}

TEST_EXPIRED_TIME = datetime.now(timezone.utc) - timedelta(hours=1)

TEST_EXPIRED_GROUP = GroupModel(
    name="test",
    membership=GroupMembershipMembers(members=[IssuerAndSubjectModel(iss=ISS, sub=SUB)]),
    expiry=TEST_EXPIRED_TIME,
)


TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA: GrantModel = GrantModel(
    subject=SUBJECT_EVERYONE,
    resource=RESOURCE_EVERYTHING,
    permissions=frozenset({P_QUERY_DATA}),
    notes="",
    expiry=None,
)
TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA_EXPIRED: GrantModel = GrantModel(
    **{
        **TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.model_dump(mode="json"),
        "expiry": TEST_EXPIRED_TIME,
    }
)

TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA: GrantModel = GrantModel(
    subject=SUBJECT_EVERYONE,
    resource=RESOURCE_PROJECT_1,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)
TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA: GrantModel = GrantModel(
    subject={"group": 0},
    resource=RESOURCE_PROJECT_1,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)
TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA_EXPIRED: GrantModel = GrantModel(
    **{
        **TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.model_dump(mode="json"),
        "expiry": TEST_EXPIRED_TIME,
    }
)
TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA: GrantModel = GrantModel(
    subject={"group": 0},
    resource=RESOURCE_PROJECT_2,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)
TEST_GRANT_GROUP_2_PROJECT_1_QUERY_DATA: GrantModel = GrantModel(
    subject={"group": 2},
    resource=RESOURCE_PROJECT_1,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)
TEST_GRANT_CLIENT_PROJECT_1_QUERY_DATA: GrantModel = GrantModel(
    subject=SUBJECT_CLIENT,
    resource=RESOURCE_PROJECT_1,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)
TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA: GrantModel = GrantModel(
    subject=SUBJECT_DAVID,
    resource=RESOURCE_PROJECT_1,
    permissions={P_QUERY_DATA},
    notes="",
    expiry=None,
)

SPECIAL_GRANT_DAVID_EVERYTHING_VIEW_EDIT_PERMISSIONS: GrantModel = GrantModel(
    subject=SUBJECT_DAVID,
    resource=RESOURCE_EVERYTHING,
    permissions={P_VIEW_PERMISSIONS, P_EDIT_PERMISSIONS},
    notes="",
    expiry=None,
)
