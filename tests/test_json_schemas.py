from fastapi.testclient import TestClient
import json
import pytest

from bento_authorization_service import json_schemas as js
from bento_authorization_service.types import Group

from . import shared_data as sd


def test_resource_schema():
    js.RESOURCE_SCHEMA_VALIDATOR.validate(sd.RESOURCE_PROJECT_1)
    js.RESOURCE_SCHEMA_VALIDATOR.validate(sd.RESOURCE_PROJECT_1_DATASET_A)
    js.RESOURCE_SCHEMA_VALIDATOR.validate(sd.RESOURCE_PROJECT_1_DATASET_B)
    js.RESOURCE_SCHEMA_VALIDATOR.validate(sd.RESOURCE_PROJECT_2)


@pytest.mark.parametrize("group, _is_member", sd.TEST_GROUPS)
def test_group_schema(group: Group, _is_member: bool):
    js.GROUP_SCHEMA_VALIDATOR.validate(group)


PARTIAL_IDS_AND_SCHEMAS = (
    ("subject_iss_client", js.SUBJECT_ISSUER_AND_CLIENT_ID),
    ("subject_iss_sub", js.SUBJECT_ISSUER_AND_SUBJECT_ID),
    ("subject", js.SUBJECT_SCHEMA),
    ("resource", js.RESOURCE_SCHEMA),
    ("group_membership", js.GROUP_MEMBERSHIP_SCHEMA),
    ("group", js.GROUP_SCHEMA),
)


# noinspection PyUnusedLocal
@pytest.mark.parametrize("partial_id, schema", PARTIAL_IDS_AND_SCHEMAS)
def test_schema_endpoints(partial_id: str, schema: dict, test_client: TestClient, db_cleanup):
    res = test_client.get(f"/schemas/{partial_id}.json")
    assert res.status_code == 200
    assert json.dumps(schema, sort_keys=True) == json.dumps(res.json(), sort_keys=True)
