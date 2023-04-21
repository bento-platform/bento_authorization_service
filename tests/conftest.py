import jwt
import pytest
import pytest_asyncio

from fastapi.testclient import TestClient
from functools import lru_cache

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database
from bento_authorization_service.main import app
from bento_authorization_service.idp_manager import BaseIdPManager, get_idp_manager


class MockIdPManager(BaseIdPManager):

    async def initialize(self):
        pass

    @property
    def initialized(self) -> bool:
        return True

    async def decode(self, token: str) -> dict:
        return jwt.decode(token, verify=False)


@lru_cache()
def get_mock_idp_manager():
    return MockIdPManager("")


@pytest.fixture
def test_client():
    with TestClient(app) as client:
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest_asyncio.fixture
async def db():
    db_instance = Database(get_config().database_uri)
    await db_instance.initialize()
    yield db_instance
    await db_instance.close()
