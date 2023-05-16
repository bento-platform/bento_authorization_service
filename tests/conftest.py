import asyncio
import asyncpg
import pytest
import pytest_asyncio

from fastapi.testclient import TestClient
from functools import lru_cache
from typing import AsyncGenerator

import os

os.environ["BENTO_DEBUG"] = "true"

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database, get_db
from bento_authorization_service.main import app
from bento_authorization_service.idp_manager import (
    BaseIdPManager,
    get_idp_manager,
)

from .shared_data import (
    TEST_TOKEN_SECRET,
    TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS,
    TEST_DISABLED_TOKEN_SIGNING_ALGOS,
    TEST_TOKEN_AUD,
    bootstrap_meta_permissions_for_david,
    make_fresh_david_token_encoded,
)


class MockIdPManager(BaseIdPManager):
    async def initialize(self):
        self._initialized = True

    def get_supported_token_signing_algs(self) -> frozenset[str]:
        return TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS

    async def decode(self, token: str) -> dict:
        return self._verify_token_and_decode(token, TEST_TOKEN_SECRET)


async def get_test_db() -> AsyncGenerator[Database, None]:
    db_instance = Database(get_config().database_uri)
    await db_instance.initialize(pool_size=1)  # Small pool size for testing
    await bootstrap_meta_permissions_for_david(db_instance)
    # try:
    # app.state.db = db_instance
    yield db_instance
    # finally:
    #     await db_instance.close()


db_fixture = pytest_asyncio.fixture(get_test_db, name="db")


@pytest_asyncio.fixture
async def db_cleanup(db: Database):
    yield
    conn: asyncpg.Connection
    async with db.connect() as conn:
        await conn.execute("DROP TABLE IF EXISTS groups")
        await conn.execute("DROP TABLE IF EXISTS grant_permissions")
        await conn.execute("DROP TABLE IF EXISTS grants")
        await conn.execute("DROP TABLE IF EXISTS samples")
        await conn.execute("DROP TABLE IF EXISTS resources")
    await db.close()


@lru_cache()
def get_mock_idp_manager():
    return MockIdPManager("", TEST_TOKEN_AUD, frozenset(TEST_DISABLED_TOKEN_SIGNING_ALGOS), True)


# noinspection PyUnusedLocal
@pytest.fixture
def test_client(db: Database):
    with TestClient(app) as client:
        app.dependency_overrides[get_db] = get_test_db
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest_asyncio.fixture
async def idp_manager():
    idp_manager_instance = MockIdPManager("", TEST_TOKEN_AUD, frozenset(TEST_DISABLED_TOKEN_SIGNING_ALGOS), True)
    await idp_manager_instance.initialize()
    yield idp_manager_instance


@pytest.fixture()
def token_encoded() -> str:
    yield make_fresh_david_token_encoded()


@pytest.fixture()
def auth_headers(token_encoded: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token_encoded}"}


# noinspection PyUnusedLocal
@pytest.fixture(scope="session")
def event_loop(request):
    # Create an instance of the default event loop for each test case.
    # See https://github.com/pytest-dev/pytest-asyncio/issues/38#issuecomment-264418154
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
