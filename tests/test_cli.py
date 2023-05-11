import pytest
from bento_authorization_service.cli import main
from bento_authorization_service.db import Database
from bento_authorization_service.policy_engine.permissions import PERMISSIONS


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_permissions(capsys, db_cleanup):
    await main(["list-permissions"])
    captured = capsys.readouterr()
    assert captured.out == "\n".join(PERMISSIONS) + "\n"


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_cli_list_grants(capsys, db: Database, db_cleanup):
    await main(["list-grants"])
    captured = capsys.readouterr()

    # Default grant set for testing purposes:
    assert captured.out == "\n".join(map(lambda x: x.json(sort_keys=True), await db.get_grants())) + "\n"
