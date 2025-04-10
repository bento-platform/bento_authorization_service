import pytest

from bento_lib.auth.permissions import P_QUERY_DATA, P_QUERY_PROJECT_LEVEL_BOOLEAN, P_DELETE_DATA
from fastapi import status
from fastapi.testclient import TestClient
from pydantic import BaseModel, RootModel
from structlog.stdlib import BoundLogger

from bento_authorization_service.db import Database
from bento_authorization_service.idp_manager import IdPManager
from bento_authorization_service.policy_engine.evaluation import (
    InvalidSubject,
    check_token_against_issuer_based_model_obj,
    check_if_token_is_in_group,
    check_if_token_matches_subject,
    resource_is_equivalent_or_contained,
    filter_matching_grants,
    determine_permissions,
    evaluate,
)
from bento_authorization_service.models import (
    BaseIssuerModel,
    IssuerAndClientModel,
    IssuerAndSubjectModel,
    GroupModel,
    GrantModel,
)

from . import shared_data as sd
from .utils import compare_via_json


class FakeIssBased(BaseIssuerModel):
    evil: str = ">:)"


class FakeGroupType1(BaseModel):
    expiry: None = None
    membership: str = ">:("


class FakeSubjectType1Inner(BaseModel):
    evil: str = "eeeevil"


FakeSubjectType1 = RootModel(FakeSubjectType1Inner)
FakeResource = RootModel(int | str)
fake_resource = FakeResource.model_validate(4)

VALID_EVALUATE_ONE_BODY = {
    "resource": sd.RESOURCE_PROJECT_1.model_dump(mode="json"),
    "permission": P_QUERY_DATA,
}


def test_token_issuer_based_comparison():
    assert not check_token_against_issuer_based_model_obj(sd.TEST_TOKEN, IssuerAndSubjectModel(iss="other", sub=sd.SUB))

    assert check_token_against_issuer_based_model_obj(sd.TEST_TOKEN, IssuerAndSubjectModel(iss=sd.ISS, sub=sd.SUB))
    assert not check_token_against_issuer_based_model_obj(sd.TEST_TOKEN, IssuerAndSubjectModel(iss=sd.ISS, sub="other"))

    assert check_token_against_issuer_based_model_obj(sd.TEST_TOKEN, IssuerAndClientModel(iss=sd.ISS, client=sd.CLIENT))
    assert not check_token_against_issuer_based_model_obj(
        sd.TEST_TOKEN, IssuerAndClientModel(iss=sd.ISS, client="other")
    )

    with pytest.raises(NotImplementedError):
        check_token_against_issuer_based_model_obj(sd.TEST_TOKEN, FakeIssBased(iss=sd.ISS))


def test_invalid_group_membership():
    with pytest.raises(NotImplementedError):
        # noinspection PyTypeChecker
        check_if_token_is_in_group(sd.TEST_TOKEN, FakeGroupType1())


#         check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {}})
#     with pytest.raises(InvalidGroupMembership):  # Must not be a malformatted member
#         check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {"members": [{"bad": True}]}})
#     with pytest.raises(InvalidGroupMembership):  # Must specify client or subject
#         check_if_token_is_in_group(sd.TEST_TOKEN, {"id": 1000, "membership": {"members": [{"iss": sd.ISS}]}})


def test_group_expiry():
    assert not check_if_token_is_in_group(sd.TEST_TOKEN, sd.TEST_EXPIRED_GROUP)


@pytest.mark.parametrize("group, is_member", sd.TEST_GROUPS)
def test_group_membership(group: GroupModel, is_member: bool):
    assert not check_if_token_is_in_group(None, group)
    assert check_if_token_is_in_group(sd.TEST_TOKEN, group) == is_member
    assert not check_if_token_is_in_group(sd.TEST_TOKEN_FOREIGN_ISS, group)  # All groups have local issuer


@pytest.mark.parametrize(
    "groups_dict, token, subject, res",
    (
        # Everyone:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.subject, True),
        # Everyone (even foreign issuer):
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_FOREIGN_ISS, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.subject, True),
        # No token:
        (sd.TEST_GROUPS_DICT, None, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.subject, True),
        # Everyone:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA.subject, True),
        # Members of group 0 (iss/client-based):
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.subject, True),
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_NOT_DAVID, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.subject, True),
        # NOT a member of group 2:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_2_PROJECT_1_QUERY_DATA.subject, False),
        # Client grant:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_CLIENT_PROJECT_1_QUERY_DATA.subject, True),
        # David:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN, sd.TEST_GRANT_CLIENT_PROJECT_1_QUERY_DATA.subject, True),
        # NOT David:
        (sd.TEST_GROUPS_DICT, sd.TEST_TOKEN_NOT_DAVID, sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA.subject, False),
    ),
)
def test_subject_match(groups_dict, token, subject, res, logger: BoundLogger):
    assert check_if_token_matches_subject(groups_dict, token, subject, logger) == res


def test_invalid_subject(logger: BoundLogger):
    # Missing group raise:
    with pytest.raises(InvalidSubject):
        # No groups defined
        check_if_token_matches_subject({}, sd.TEST_TOKEN, sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.subject, logger)

    # New subject type (not handled):
    with pytest.raises(NotImplementedError):
        # noinspection PyTypeChecker
        check_if_token_matches_subject(
            {}, sd.TEST_TOKEN, FakeSubjectType1.model_validate(FakeSubjectType1Inner()), logger
        )


def test_resource_match(logger: BoundLogger):
    # equivalent: both everything
    assert resource_is_equivalent_or_contained(
        sd.RESOURCE_EVERYTHING, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.resource, logger
    )
    assert resource_is_equivalent_or_contained(
        sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.resource, sd.RESOURCE_EVERYTHING, logger
    )

    # Project 1 is a subset of everything:
    assert resource_is_equivalent_or_contained(
        sd.RESOURCE_PROJECT_1_DATASET_A, sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.resource, logger
    )
    # ... but everything is not contained in / equivalent to Project 1
    assert not resource_is_equivalent_or_contained(
        sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA.resource, sd.RESOURCE_PROJECT_1_DATASET_A, logger
    )

    # Permission applies to Project 1, but we are checking for Everything, so it should be False:
    assert not resource_is_equivalent_or_contained(
        sd.RESOURCE_EVERYTHING, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA.resource, logger
    )

    # Same project, optionally requesting a specific dataset of the project
    assert resource_is_equivalent_or_contained(
        sd.RESOURCE_PROJECT_1, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA.resource, logger
    )
    assert resource_is_equivalent_or_contained(
        sd.RESOURCE_PROJECT_1_DATASET_A, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA.resource, logger
    )


@pytest.mark.parametrize(
    "r1, r2",
    (
        (sd.RESOURCE_EVERYTHING, fake_resource),
        (fake_resource, sd.RESOURCE_EVERYTHING),
        (sd.RESOURCE_PROJECT_1_DATASET_A, fake_resource),
        (fake_resource, sd.TEST_GRANT_EVERYONE_PROJECT_1_QUERY_DATA.resource),
    ),
)
def test_invalid_resource(r1, r2, logger: BoundLogger):
    # Fake resources, raise NotImplementedError
    with pytest.raises(NotImplementedError):
        # noinspection PyTypeChecker
        resource_is_equivalent_or_contained(r1, r2, logger)


@pytest.mark.parametrize(
    "args, num_matching, true_permissions_set",
    (
        (
            (
                (
                    sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA,
                    sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA_EXPIRED,  # Won't apply - expired
                    sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
                ),
                sd.TEST_GROUPS_DICT,
                sd.TEST_TOKEN,
                sd.RESOURCE_PROJECT_1_DATASET_A,
            ),
            2,
            frozenset(
                {
                    # original permission
                    P_QUERY_DATA,
                    # from gives
                    *P_QUERY_DATA.gives,
                }
            ),
        ),
        (
            (
                (sd.TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA,),
                sd.TEST_GROUPS_DICT,
                sd.TEST_TOKEN,
                sd.RESOURCE_PROJECT_1_DATASET_A,
            ),
            0,  # Wrong project
            frozenset(),
        ),
        (
            (
                (sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA_EXPIRED,),
                sd.TEST_GROUPS_DICT,
                sd.TEST_TOKEN,
                sd.RESOURCE_PROJECT_1_DATASET_A,
            ),
            0,  # Expired
            frozenset(),
        ),
        (
            # Missing group - will throw SubjectError which will get caught and logged
            ((sd.TEST_GRANT_GROUP_0_PROJECT_2_QUERY_DATA,), {}, sd.TEST_TOKEN, sd.RESOURCE_PROJECT_1_DATASET_A),
            0,
            frozenset(),
        ),
    ),
)
def test_grant_permissions_set(args, num_matching, true_permissions_set, logger):
    full_args = (*args, logger)
    matching_token = tuple(filter_matching_grants(*full_args))
    permissions_set = determine_permissions(*full_args)
    assert len(matching_token) == num_matching  # Missing group definition, so doesn't apply
    assert permissions_set == true_permissions_set


def test_grant_filtering_1(logger: BoundLogger):
    matching_token = tuple(
        filter_matching_grants(
            (
                sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA,
                sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
            ),
            sd.TEST_GROUPS_DICT,
            sd.TEST_TOKEN_FOREIGN_ISS,
            sd.RESOURCE_PROJECT_1_DATASET_A,
            logger,
        )
    )
    assert len(matching_token) == 1  # Everyone + everything applies, but not grant 2 (foreign issuer, not in group 0)


def test_grant_filtering_2(logger: BoundLogger):
    matching_token = tuple(
        filter_matching_grants(
            (
                sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA_EXPIRED,  # Won't apply - expired
                sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA,
            ),
            sd.TEST_GROUPS_DICT,
            sd.TEST_TOKEN_FOREIGN_ISS,
            sd.RESOURCE_PROJECT_1_DATASET_A,
            logger,
        )
    )
    assert len(matching_token) == 0  # Foreign issuer, not in group 0


async def _eval_test_data(db: Database):
    group_id = await db.create_group(sd.TEST_GROUPS[0][0])
    grant_with_group = {
        **sd.TEST_GRANT_GROUP_0_PROJECT_1_QUERY_DATA.model_dump(mode="json"),
        "subject": {"group": group_id},
    }
    await db.create_grant(GrantModel(**grant_with_group))
    return sd.make_fresh_david_token_encoded()


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_function(db: Database, idp_manager: IdPManager, logger, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)

    # directly given query:data
    res = await evaluate(idp_manager, db, logger, tkn, (sd.RESOURCE_PROJECT_1,), (P_QUERY_DATA,))
    assert res

    # indirectly (via gives=) given project-level boolean
    res = await evaluate(idp_manager, db, logger, tkn, (sd.RESOURCE_PROJECT_1,), (P_QUERY_PROJECT_LEVEL_BOOLEAN,))
    assert res


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_permissions_endpoint(db: Database, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post(
        "/policy/permissions",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "resources": [sd.RESOURCE_PROJECT_1.model_dump(mode="json")],
        },
    )
    assert res.status_code == status.HTTP_200_OK
    assert P_QUERY_DATA in res.json()["result"][0]


PERMISSIONS_RESOURCES_LIST = {
    "resources": [
        sd.RESOURCE_PROJECT_1.model_dump(mode="json"),
        sd.RESOURCE_PROJECT_2.model_dump(mode="json"),
    ],
}


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_permissions_endpoint_list(db: Database, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post(
        "/policy/permissions", headers={"Authorization": f"Bearer {tkn}"}, json=PERMISSIONS_RESOURCES_LIST
    )
    assert res.status_code == status.HTTP_200_OK
    res_json = res.json()
    assert P_QUERY_DATA in res_json["result"][0]
    assert P_QUERY_DATA not in res_json["result"][1]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_permissions_endpoint_list_expired_token(db: Database, test_client: TestClient, db_cleanup):
    await _eval_test_data(db)
    tkn = sd.make_fresh_david_token_encoded(exp_offset=-10)
    res = test_client.post(
        "/policy/permissions", headers={"Authorization": f"Bearer {tkn}"}, json=PERMISSIONS_RESOURCES_LIST
    )
    assert res.status_code == status.HTTP_200_OK  # 'fine', but no permissions - expired token
    assert res.json()["result"] == [[], []]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_permissions_endpoint_map(db: Database, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post(
        "/policy/permissions_map", headers={"Authorization": f"Bearer {tkn}"}, json=PERMISSIONS_RESOURCES_LIST
    )
    assert res.status_code == status.HTTP_200_OK
    res_json = res.json()
    assert len(res_json["result"]) == 2
    assert res_json["result"][0][P_QUERY_DATA]
    assert not res_json["result"][0][P_DELETE_DATA]
    assert not res_json["result"][1][P_QUERY_DATA]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_permissions_endpoint_map_expired_token(db: Database, test_client: TestClient, db_cleanup):
    await _eval_test_data(db)
    tkn = sd.make_fresh_david_token_encoded(exp_offset=-10)
    res = test_client.post(
        "/policy/permissions_map", headers={"Authorization": f"Bearer {tkn}"}, json=PERMISSIONS_RESOURCES_LIST
    )
    assert res.status_code == status.HTTP_200_OK  # 'fine', but no permissions - expired token
    assert not res.json()["result"][0][P_QUERY_DATA]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_endpoint(db: Database, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "resources": [sd.RESOURCE_PROJECT_1.model_dump(mode="json")],
            "permissions": [P_QUERY_DATA],
        },
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["result"][0][0]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_one_endpoint(db: Database, test_client: TestClient, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post(
        "/policy/evaluate_one",
        headers={"Authorization": f"Bearer {tkn}"},
        json=VALID_EVALUATE_ONE_BODY,
    )
    assert res.status_code == status.HTTP_200_OK
    r = res.json()["result"]
    assert isinstance(r, bool)
    assert r


TWO_PROJECT_DATA_QUERY = {**PERMISSIONS_RESOURCES_LIST, "permissions": [P_QUERY_DATA]}


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_endpoint_list(db: Database, test_client: TestClient, auth_headers, db_cleanup):
    tkn = await _eval_test_data(db)
    res = test_client.post("/policy/evaluate", headers={"Authorization": f"Bearer {tkn}"}, json=TWO_PROJECT_DATA_QUERY)
    assert res.status_code == status.HTTP_200_OK
    assert compare_via_json(res.json()["result"], [[True], [False]])


VIEW_PERMS_GRANT = grant = {
    "resource": sd.RESOURCE_PROJECT_1,
    "permissions": {sd.P_VIEW_PERMISSIONS},
    "notes": "",
    "expiry": None,
    "subject": {"iss": sd.ISS, "sub": sd.SUB},
}


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_seperate_subject(db: Database, test_client: TestClient, auth_headers, db_cleanup):
    tkn = sd.make_fresh_david_token_encoded()
    await db.create_grant(GrantModel.model_validate(VIEW_PERMS_GRANT))

    res = test_client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "token_data": {},  # Empty token data <-> 'no token'
            "resources": [sd.RESOURCE_PROJECT_1.model_dump(mode="json")],
            "permissions": [P_QUERY_DATA],
        },
    )
    assert res.status_code == status.HTTP_200_OK
    assert not res.json()["result"][0][0]


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_one_seperate_subject(db: Database, test_client: TestClient, auth_headers, db_cleanup):
    tkn = sd.make_fresh_david_token_encoded()
    await db.create_grant(GrantModel.model_validate(VIEW_PERMS_GRANT))

    res = test_client.post(
        "/policy/evaluate_one",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "token_data": {},  # Empty token data <-> 'no token'
            "resource": sd.RESOURCE_PROJECT_1.model_dump(mode="json"),
            "permission": P_QUERY_DATA,
        },
    )
    assert res.status_code == status.HTTP_200_OK
    r = res.json()["result"]
    assert isinstance(r, bool)
    assert not r


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_seperate_subject_multiple(db: Database, test_client: TestClient, auth_headers, db_cleanup):
    tkn = sd.make_fresh_david_token_encoded()
    await db.create_grant(GrantModel.model_validate(VIEW_PERMS_GRANT))

    res = test_client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "token_data": {},  # Empty token data <-> 'no token'
            "resources": [
                sd.RESOURCE_PROJECT_1.model_dump(mode="json"),
                sd.RESOURCE_PROJECT_2.model_dump(mode="json"),
            ],
            "permissions": [P_QUERY_DATA],
        },
    )
    assert res.status_code == status.HTTP_200_OK
    assert compare_via_json(res.json()["result"], [[False], [False]])


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_seperate_subject_denied(db: Database, test_client: TestClient, auth_headers, db_cleanup):
    tkn = sd.make_fresh_non_david_token_encoded()
    res = test_client.post(
        "/policy/evaluate",
        headers={"Authorization": f"Bearer {tkn}"},
        json={
            "token_data": {},  # Empty token data <-> 'no token'
            "resources": [sd.RESOURCE_PROJECT_1.model_dump(mode="json")],
            "permissions": [P_QUERY_DATA],
        },
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN


# noinspection PyUnusedLocal
def test_evaluate_non_jwt_token(test_client: TestClient, db_cleanup):
    res = test_client.post("/policy/evaluate", headers={"Authorization": "Bearer eee"}, json=TWO_PROJECT_DATA_QUERY)
    assert res.status_code == status.HTTP_400_BAD_REQUEST


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_bad_audience_token(db: Database, test_client: TestClient, db_cleanup):
    await _eval_test_data(db)
    tkn = sd.make_fresh_david_token_encoded(audience="invalid")
    res = test_client.post("/policy/evaluate", headers={"Authorization": f"Bearer {tkn}"}, json=TWO_PROJECT_DATA_QUERY)
    assert res.status_code == status.HTTP_200_OK  # 'fine', but no permissions - bad audience
    assert compare_via_json(res.json()["result"], [[False], [False]])


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_expired_token(db: Database, test_client: TestClient, db_cleanup):
    await _eval_test_data(db)
    tkn = sd.make_fresh_david_token_encoded(exp_offset=-10)
    res = test_client.post("/policy/evaluate", headers={"Authorization": f"Bearer {tkn}"}, json=TWO_PROJECT_DATA_QUERY)
    assert res.status_code == status.HTTP_200_OK  # 'fine', but no permissions - expired token
    assert compare_via_json(res.json()["result"], [[False], [False]])


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_evaluate_one_expired_token(db: Database, test_client: TestClient, db_cleanup):
    await _eval_test_data(db)
    tkn = sd.make_fresh_david_token_encoded(exp_offset=-10)
    res = test_client.post(
        "/policy/evaluate_one", headers={"Authorization": f"Bearer {tkn}"}, json=VALID_EVALUATE_ONE_BODY
    )
    assert res.status_code == status.HTTP_200_OK  # 'fine', but no permissions - expired token
    assert not res.json()["result"]
