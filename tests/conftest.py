import asyncpg
import jwt
import pytest
import pytest_asyncio

from fastapi.testclient import TestClient
from functools import lru_cache
from typing import AsyncGenerator

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database, get_db
from bento_authorization_service.main import app
from bento_authorization_service.idp_manager import BaseIdPManager, get_idp_manager, check_token_signing_alg

from .shared_data import TEST_TOKEN_SECRET, TEST_TOKEN_SIGNING_ALG, bootstrap_meta_permissions_for_david


class MockIdPManager(BaseIdPManager):
    async def initialize(self):
        pass

    @property
    def initialized(self) -> bool:
        return True

    async def decode(self, token: str) -> dict:
        decoded_token = jwt.decode(
            token,
            TEST_TOKEN_SECRET,
            audience=TEST_TOKEN_SECRET,
            algorithms=[TEST_TOKEN_SIGNING_ALG],
        )  # hard-coded test secret

        # hard-coded permitted algos
        check_token_signing_alg(decoded_token, frozenset([TEST_TOKEN_SIGNING_ALG]))
        return decoded_token


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
    return MockIdPManager("")


# noinspection PyUnusedLocal
@pytest.fixture
def test_client(db: Database):
    with TestClient(app) as client:
        app.dependency_overrides[get_db] = get_test_db
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest_asyncio.fixture
async def idp_manager():
    idp_manager_instance = MockIdPManager("")
    await idp_manager_instance.initialize()
    yield idp_manager_instance
