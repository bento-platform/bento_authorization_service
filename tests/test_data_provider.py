import json
from pathlib import Path

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from bento_authorization_service.data_provider.provider import AuthzDataProvider, get_authz_data_provider
from bento_authorization_service.db import Database, DatabaseDependency
from bento_authorization_service.main import app
from bento_authorization_service.models import GroupModel

from . import shared_data as sd
from .utils import compare_model_json

# Static data is stored with strictly negative IDs, so the single grant and group below both get ID -1.
STATIC_GRANT_EVERYONE = sd.TEST_GRANT_EVERYONE_EVERYTHING_QUERY_DATA
STATIC_GROUP_DAVID = GroupModel.model_validate(
    {"name": "static group", "membership": {"members": [{"iss": sd.ISS, "sub": sd.SUB}]}, "expiry": None}
)
# TODO: test static grant pointing to a static group


@pytest.fixture
def static_data_file(tmp_path: Path) -> Path:
    path = tmp_path / "static_authz_data.json"
    path.write_text(
        json.dumps(
            {
                "grants": [STATIC_GRANT_EVERYONE.model_dump(mode="json")],
                "groups": [STATIC_GROUP_DAVID.model_dump(mode="json")],
            }
        )
    )
    return path


@pytest.fixture
def static_provider_override(static_data_file: Path):
    def _get_provider(db: DatabaseDependency) -> AuthzDataProvider:
        return AuthzDataProvider(db, static_data_file)

    app.dependency_overrides[get_authz_data_provider] = _get_provider
    yield
    app.dependency_overrides.pop(get_authz_data_provider, None)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_provider_static_grants(db: Database, db_cleanup, static_data_file: Path):
    provider = AuthzDataProvider(db, static_data_file)

    grant = await provider.get_grant(-1)
    assert grant is not None and grant.id == -1 and not grant.mutable
    assert compare_model_json(grant, STATIC_GRANT_EVERYONE, exclude={"id", "created", "mutable"})
    assert await provider.get_grant(-99) is None
    assert -1 in {g.id for g in await provider.get_grants()}


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_provider_static_groups(db: Database, db_cleanup, static_data_file: Path):
    provider = AuthzDataProvider(db, static_data_file)

    group = await provider.get_group(-1)
    assert group is not None and group.id == -1 and not group.mutable
    assert compare_model_json(group, STATIC_GROUP_DAVID, exclude={"id", "created", "mutable"})
    assert await provider.get_group(-99) is None
    assert -1 in {g.id for g in await provider.get_groups()}


# noinspection PyUnusedLocal
def test_grant_endpoints_static(
    auth_headers: dict[str, str], test_client: TestClient, db_cleanup, static_provider_override
):
    res = test_client.get("/grants/-1", headers=auth_headers)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["id"] == -1
    assert data["mutable"] is False

    # static grants can't be deleted - mutating endpoints only look in the database
    res = test_client.delete("/grants/-1", headers=auth_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND


# noinspection PyUnusedLocal
def test_group_endpoints_static(
    auth_headers: dict[str, str], test_client: TestClient, db_cleanup, static_provider_override
):
    res = test_client.get("/groups/-1", headers=auth_headers)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["id"] == -1
    assert data["mutable"] is False

    # static groups can't be deleted - mutating endpoints only look in the database
    res = test_client.delete("/groups/-1", headers=auth_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND
