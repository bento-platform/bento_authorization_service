import jwt
import pytest
import pytest_asyncio

from fastapi.testclient import TestClient
from functools import lru_cache
from typing import AsyncGenerator

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database, get_db
from bento_authorization_service.main import app
from bento_authorization_service.idp_manager import BaseIdPManager, get_idp_manager


class MockIdPManager(BaseIdPManager):

    async def initialize(self):
        pass

    @property
    def initialized(self) -> bool:
        return True

    async def decode(self, token: str) -> dict:
        return jwt.decode(token, "secret", audience="account", algorithms=["HS256"])  # hard-coded test secret


async def get_test_db() -> AsyncGenerator[Database, None]:
    db_ = Database(get_config().database_uri)
    await db_.initialize()
    try:
        yield db_
    finally:
        await db_.close()


@lru_cache()
def get_mock_idp_manager():
    return MockIdPManager("")


@pytest.fixture
def test_client():
    with TestClient(app) as client:
        app.dependency_overrides[get_db] = get_test_db
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest_asyncio.fixture
async def db():
    db_instance = Database(get_config().database_uri)
    await db_instance.initialize()
    yield db_instance
    await db_instance.close()


@pytest_asyncio.fixture
async def idp_manager():
    idp_manager_instance = MockIdPManager("")
    await idp_manager_instance.initialize()
    yield idp_manager_instance
