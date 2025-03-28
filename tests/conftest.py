import asyncio
import asyncpg
import logging
import os
import pytest
import pytest_asyncio
import structlog.stdlib

from fastapi.testclient import TestClient
from functools import lru_cache
from typing import AsyncGenerator

os.environ["BENTO_AUTHZ_ENABLED"] = "false"
os.environ["BENTO_DEBUG"] = "true"
os.environ["BENTO_JSON_LOGS"] = "false"
os.environ["CORS_ORIGINS"] = "*"

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database, get_db
from bento_authorization_service.logger import get_logger
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


@pytest.fixture(name="log_output")
def fixture_log_output():
    # INFO: see https://www.structlog.org/en/stable/testing.html
    return structlog.testing.LogCapture()


@pytest.fixture(autouse=True)
def fixture_configure_structlog(log_output):
    logging.getLogger("asyncio").setLevel(logging.WARN)
    logging.getLogger("httpx").setLevel(logging.WARN)

    # INFO: see https://www.structlog.org/en/stable/testing.html
    structlog.configure(processors=[log_output])


async def get_test_db() -> AsyncGenerator[Database, None]:
    db_instance = Database(get_config().database_uri)
    r = await db_instance.initialize(pool_size=1)  # Small pool size for testing
    if r:
        # if we're initializing for the first time in this test -> cleanup flow, bootstrap permissions for the "david"
        # test user.
        await bootstrap_meta_permissions_for_david(db_instance)
    yield db_instance


async def get_test_db_no_bootstrap() -> AsyncGenerator[Database, None]:
    # same as the above, but without the default permissions - useful for testing database pool initialization/closing,
    # or grant creation starting from a fresh database.
    db_instance = Database(get_config().database_uri)
    await db_instance.initialize(pool_size=1)  # Small pool size for testing
    yield db_instance


db_fixture = pytest_asyncio.fixture(get_test_db, name="db")
db_fixture_no_bootstrap = pytest_asyncio.fixture(get_test_db_no_bootstrap, name="db_no")


async def _clean_db(db: Database):
    conn: asyncpg.Connection
    async with db.connect() as conn:
        await conn.execute("DROP TABLE IF EXISTS groups")
        await conn.execute("DROP TABLE IF EXISTS grant_permissions")
        await conn.execute("DROP TABLE IF EXISTS grants")
        await conn.execute("DROP TABLE IF EXISTS samples")
        await conn.execute("DROP TABLE IF EXISTS resources")
    await db.close()


@pytest_asyncio.fixture
async def db_cleanup(db: Database):
    yield
    await _clean_db(db)


@pytest_asyncio.fixture
async def db_cleanup_no(db_no: Database):
    yield
    await _clean_db(db_no)


@lru_cache()
def get_mock_idp_manager():
    logger = structlog.stdlib.get_logger("test_logger")
    return MockIdPManager(logger, "", TEST_TOKEN_AUD, frozenset(TEST_DISABLED_TOKEN_SIGNING_ALGOS), True)


# noinspection PyUnusedLocal
@pytest.fixture
def test_client(db: Database):
    with TestClient(app) as client:
        app.dependency_overrides[get_db] = get_test_db
        app.dependency_overrides[get_idp_manager] = get_mock_idp_manager
        yield client


@pytest.fixture(name="logger")
def fixture_logger() -> structlog.stdlib.BoundLogger:
    return get_logger(get_config())


@pytest_asyncio.fixture
async def idp_manager(logger: structlog.stdlib.BoundLogger):
    idp_manager_instance = MockIdPManager(
        logger, "", TEST_TOKEN_AUD, frozenset(TEST_DISABLED_TOKEN_SIGNING_ALGOS), True
    )
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
