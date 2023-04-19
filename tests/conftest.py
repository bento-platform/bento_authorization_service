import pytest
from fastapi.testclient import TestClient


import sys
print(sys.version_info)


from bento_authorization_service.main import app


@pytest.fixture
def test_client():
    yield TestClient(app)
