import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from bento_authorization_service.db import db as db_instance
from bento_authorization_service.main import app


@pytest.fixture
def test_client():
    yield TestClient(app)


@pytest_asyncio.fixture
async def db():
    await db_instance.initialize()
    yield db_instance
