from fastapi.testclient import TestClient


# noinspection PyUnusedLocal
def test_service_info(test_client: TestClient, db_cleanup):
    response = test_client.get("/service-info")
    assert response.status_code == 200
    # TODO
