import pytest
from bento_authorization_service.policy_engine.evaluation import InvalidGrant, check_if_grant_subject_matches_token
from bento_authorization_service.types import Grant
from . import shared_data as sd


def test_bad_grant_subject():
    # noinspection PyTypeChecker
    bad_grant: Grant = {**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA, "subject": {}}
    with pytest.raises(InvalidGrant):
        check_if_grant_subject_matches_token({}, sd.TEST_TOKEN, bad_grant)

    # noinspection PyTypeChecker
    bad_grant: Grant = {**sd.TEST_GRANT_DAVID_PROJECT_1_QUERY_DATA, "subject": {"iss": sd.ISS}}
    with pytest.raises(InvalidGrant):
        check_if_grant_subject_matches_token({}, sd.TEST_TOKEN, bad_grant)
