import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from bento_authorization_service.config import config
from bento_authorization_service.db import Database
from bento_authorization_service.main import app


@pytest.fixture
def test_client():
    yield TestClient(app)


@pytest_asyncio.fixture
async def db():
    db_instance = Database(config.database_uri)
    await db_instance.initialize()
    yield db_instance
    await db_instance.close()
