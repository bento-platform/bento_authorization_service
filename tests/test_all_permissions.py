from bento_lib.auth.permissions import PERMISSIONS
from fastapi import status
from fastapi.testclient import TestClient


def test_grant_endpoints_create(test_client: TestClient):
    res = test_client.get("/all_permissions/")
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert len(data) == len(PERMISSIONS)
    assert len(list(data[0].keys())) == 6
