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
from bento_authorization_service.idp_manager import (
    BaseIdPManager,
    get_idp_manager,
    check_token_signing_alg,
    get_permitted_id_token_signing_alg_values,
    verify_id_token_and_decode,
)

from .shared_data import (
    TEST_TOKEN_SECRET,
    TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS,
    TEST_DISABLED_TOKEN_SIGNING_ALGOS,
    bootstrap_meta_permissions_for_david,
    TEST_TOKEN_AUD,
    bootstrap_meta_permissions_for_david,
    make_fresh_david_token_encoded,
)


class MockIdPManager(BaseIdPManager):
    async def initialize(self):
        pass

    @property
    def initialized(self) -> bool:
        return True

    async def decode(self, token: str) -> dict:
        return verify_id_token_and_decode(
            token, TEST_TOKEN_SECRET, TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS, TEST_DISABLED_TOKEN_SIGNING_ALGOS
        )


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
    return MockIdPManager("", TEST_TOKEN_AUD, True)


# noinspection PyUnusedLocal
@pytest.fixture
def test_client(db: Database):
    with TestClient(app) as client:
        app.dependency_overrides[get_db] = get_test_db
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest_asyncio.fixture
async def idp_manager():
    idp_manager_instance = MockIdPManager("", TEST_TOKEN_AUD, True)
    await idp_manager_instance.initialize()
    yield idp_manager_instance


@pytest.fixture()
def token_encoded() -> str:
    yield make_fresh_david_token_encoded()


@pytest.fixture()
def auth_headers(token_encoded: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token_encoded}"}
