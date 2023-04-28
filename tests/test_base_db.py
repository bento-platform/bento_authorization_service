import pytest
from bento_authorization_service.db import Database


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_db_open_close(db: Database, db_cleanup):
    await db.close()
    assert db._pool is None

    # duplicate request: should be idempotent
    await db.close()
    assert db._pool is None

    # should not be able to connect
    async with db.connect():
        assert db._pool is not None  # Connection auto-initialized

    # try re-opening
    await db.initialize()
    assert db._pool is not None
    old_pool = db._pool

    # duplicate request: should be idempotent
    await db.initialize()
    assert db._pool == old_pool  # same instance
