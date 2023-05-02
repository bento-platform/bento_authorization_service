import json
import jsonschema
from fastapi.testclient import TestClient

from bento_authorization_service.json_schemas import TOKEN_DATA


def test_token_data_valid():
    jsonschema.Draft202012Validator.check_schema(TOKEN_DATA)


# noinspection PyUnusedLocal
def test_token_data_schema_endpoint(test_client: TestClient, db_cleanup):
    res = test_client.get(f"/schemas/token_data.json")
    assert res.status_code == 200
    assert json.dumps(TOKEN_DATA, sort_keys=True) == json.dumps(res.json(), sort_keys=True)
