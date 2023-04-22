import pytest
from bento_authorization_service.db import DatabaseError, Database


@pytest.mark.asyncio
async def test_db_open_close(db: Database):
    await db.close()
    assert db._pool is None

    # duplicate request: should be idempotent
    await db.close()
    assert db._pool is None

    # should not be able to connect
    with pytest.raises(DatabaseError):
        async with db.connect():
            pass

    # try re-opening
    await db.initialize()
    assert db._pool is not None
    old_pool = db._pool

    # duplicate request: should be idempotent
    await db.initialize()
    assert db._pool == old_pool  # same instance