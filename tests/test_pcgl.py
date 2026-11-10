import asyncio
import logging
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
import structlog
from aiohttp import web
from aiohttp.test_utils import TestServer
from bento_lib.auth.permissions import (
    P_DOWNLOAD_DATA,
    P_DOWNLOAD_METADATA,
    P_QUERY_DATA,
    P_QUERY_DATASET_LEVEL_COUNTS,
    Permission,
)
from fastapi import status
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from structlog.testing import LogCapture

from bento_authorization_service.config import Config
from bento_authorization_service.data_provider.base import BaseDataProvider
from bento_authorization_service.idp_manager import BaseIdPManager
from bento_authorization_service.main import app
from bento_authorization_service.models import ResourceModel, StoredGrantModel, StoredGroupModel, SubjectModel
from bento_authorization_service.policy_engine.dependency import get_policy_engine
from bento_authorization_service.policy_engine.evaluation import BentoPolicyEngine
from bento_authorization_service.policy_engine.pcgl import PcglPolicyEngine

from . import shared_data as sd
from .conftest import get_mock_idp_manager

PROJECT = "p1"
STUDY_A = "PCGLST0001"
STUDY_B = "PCGLST0002"

R_A_EXP = ResourceModel({"project": PROJECT, "dataset": STUDY_A, "data_type": "experiment"})
R_B_EXP = ResourceModel({"project": PROJECT, "dataset": STUDY_B, "data_type": "experiment"})
R_A = ResourceModel({"project": PROJECT, "dataset": STUDY_A})
R_A_PHENO = ResourceModel({"project": PROJECT, "dataset": STUDY_A, "data_type": "phenopacket"})
R_PROJECT = ResourceModel({"project": PROJECT})

USER_TOKEN = "user-token-value"
SERVICE_ID = "bento"
SERVICE_SECRET = "service-secret-value"


# --- helpers -----------------------------------------------------------------------------------------------------


class MemoryDataProvider(BaseDataProvider):
    def __init__(self, grants: tuple[StoredGrantModel, ...] = (), groups: tuple[StoredGroupModel, ...] = ()):
        self._grants = grants
        self._groups = groups

    async def get_grant(self, id_: int) -> StoredGrantModel | None:
        return next((g for g in self._grants if g.id == id_), None)

    async def get_grants(self) -> tuple[StoredGrantModel, ...]:
        return self._grants

    async def get_group(self, id_: int) -> StoredGroupModel | None:
        return next((g for g in self._groups if g.id == id_), None)

    async def get_groups(self) -> tuple[StoredGroupModel, ...]:
        return self._groups


def make_grant(i: int, subject: SubjectModel, resource: ResourceModel, *permissions: Permission) -> StoredGrantModel:
    return StoredGrantModel(
        id=i,
        created=datetime.now(UTC),
        mutable=False,
        subject=subject,
        resource=resource,
        expiry=None,
        permissions=frozenset(permissions),
    )


def make_policy_engine(
    idp_manager: BaseIdPManager,
    provider: BaseDataProvider | None = None,
    url: str = "http://pcgl.invalid",
    timeout: float = 5,
) -> PcglPolicyEngine:
    return PcglPolicyEngine(
        idp_manager,
        provider or MemoryDataProvider(),
        pcgl_authz_url=url,
        pcgl_service_id=SERVICE_ID,
        pcgl_service_secret=SecretStr(SERVICE_SECRET),
        pcgl_service_token_lifespan=1500,
        pcgl_action_endpoint="/export/study",
        pcgl_action_method="GET",
        pcgl_request_timeout=timeout,
        verify_ssl=False,
    )


class PcglStub:
    """Stub for PcglPolicyEngine.pcgl_allowed; records the study IDs of each call."""

    def __init__(self, allowed: set[str]):
        self.allowed = allowed
        self.calls: list[list[str]] = []

    async def __call__(self, token, study_ids, logger) -> dict[str, bool]:
        self.calls.append(list(study_ids))
        return {s: bool(token) and s in self.allowed for s in study_ids}


StubEngineFactory = Callable[..., tuple[PcglPolicyEngine, PcglStub]]


@pytest.fixture
def stub_engine(monkeypatch: pytest.MonkeyPatch, idp_manager: BaseIdPManager) -> StubEngineFactory:
    """Builds a PCGL engine over in-memory grants, with pcgl_allowed replaced by a recording stub."""

    def _make(allowed: set[str], grants: tuple[StoredGrantModel, ...] = ()) -> tuple[PcglPolicyEngine, PcglStub]:
        engine = make_policy_engine(idp_manager, MemoryDataProvider(grants))
        stub = PcglStub(allowed)
        monkeypatch.setattr(engine, "pcgl_allowed", stub)
        return engine, stub

    return _make


@pytest.fixture
def plogger(log_output: LogCapture) -> structlog.stdlib.BoundLogger:
    # Logger which always goes to the LogCapture, regardless of global structlog configuration.
    # Used to assert that decisions and errors are logged in the correct structure format.
    return structlog.stdlib.BoundLogger(logging.getLogger("test_pcgl"), [log_output], {})


# --- engine logic (PCGL call stubbed) ----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [True, False])
async def test_evaluate_follows_pcgl_for_experiment(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger, allowed: bool
):
    engine, stub = stub_engine({STUDY_A} if allowed else set())
    res = await engine.evaluate((R_A_EXP,), (P_DOWNLOAD_METADATA,), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert res == [[allowed]]
    assert stub.calls == [[STUDY_A]]


@pytest.mark.asyncio
async def test_evaluate_non_delegated_resources_never_sent(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    engine, stub = stub_engine({STUDY_A})
    resources = (R_A, R_A_PHENO, R_PROJECT, sd.RESOURCE_EVERYTHING)
    res = await engine.evaluate(resources, (P_DOWNLOAD_METADATA,), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert res == [[False]] * 4
    assert stub.calls == []


@pytest.mark.asyncio
async def test_evaluate_bento_grant_skips_pcgl(stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger):
    # Assert that PcglPolicyEngine does not override Bento authz grants.
    grants = (make_grant(1, sd.SUBJECT_DAVID, R_A, P_DOWNLOAD_METADATA),)
    engine, stub = stub_engine(set(), grants)
    res = await engine.evaluate((R_A_EXP, R_A), (P_DOWNLOAD_METADATA,), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert res == [[True], [True]]
    assert stub.calls == []


@pytest.mark.asyncio
async def test_evaluate_query_data_gives_download_metadata(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    grants = (make_grant(1, sd.SUBJECT_DAVID, R_A, P_QUERY_DATA),)
    engine, stub = stub_engine(set(), grants)
    res = await engine.evaluate(
        (R_A_EXP,), (P_QUERY_DATA, P_DOWNLOAD_METADATA), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger
    )
    assert res == [[True, True]]
    assert stub.calls == []  # Bento already gives it (query:data gives download:metadata), so PCGL isn't asked


ALL_DATA_PERMS = (P_QUERY_DATA, P_QUERY_DATASET_LEVEL_COUNTS, P_DOWNLOAD_DATA, P_DOWNLOAD_METADATA)


@pytest.mark.asyncio
async def test_evaluate_pcgl_adds_nothing_else(stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger):
    engine, _ = stub_engine({STUDY_A})
    res = await engine.evaluate((R_A_EXP,), ALL_DATA_PERMS, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    # Only flips P_DOWNLOAD_METADATA on if allowed
    assert res == [[False, False, False, True]]


@pytest.mark.asyncio
async def test_evaluate_pcgl_removes_nothing(stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger):
    grants = (
        make_grant(1, sd.SUBJECT_DAVID, R_A, P_QUERY_DATA, P_DOWNLOAD_DATA),
        make_grant(2, sd.SUBJECT_DAVID, sd.RESOURCE_EVERYTHING, P_QUERY_DATA),
    )
    # PCGL allows no studies, but that never removes Bento decisions: download:metadata (last column) comes from
    # the query:data grants (query:data gives it), so PCGL isn't even asked.
    engine, stub = stub_engine(set(), grants)
    res = await engine.evaluate(
        (R_A_EXP, R_PROJECT, sd.RESOURCE_EVERYTHING), ALL_DATA_PERMS, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger
    )
    assert res == [
        [True, True, True, True],  # Study A experiment
        [True, True, False, True],  # Project
        [True, True, False, True],  # Everything
    ]
    assert stub.calls == []


@pytest.mark.asyncio
async def test_evaluate_one_call_mixed_rows_repeated_columns(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    engine, stub = stub_engine({STUDY_A})  # Only allow STUDY_A
    resources = (R_A_EXP, R_PROJECT, R_B_EXP, R_A_EXP, R_A)  # mixed allowed/denied resources
    permissions = (P_DOWNLOAD_METADATA, P_QUERY_DATA, P_DOWNLOAD_METADATA)
    res = await engine.evaluate(resources, permissions, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert res == [
        [True, False, True],
        [False, False, False],
        [False, False, False],
        [True, False, True],
        [False, False, False],
    ]
    assert stub.calls == [[STUDY_A, STUDY_B]]  # unique studies, one call


@pytest.mark.asyncio
async def test_evaluate_anonymous_and_no_delegated_columns_skip_pcgl(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    engine, stub = stub_engine({STUDY_A})
    # Anonymous checks are not delegated to PcglPolicyEngine, default to False
    assert await engine.evaluate((R_A_EXP,), (P_DOWNLOAD_METADATA,), None, None, plogger) == [[False]]
    # Non delegated permissions default to False even for authenticated users
    assert await engine.evaluate((R_A_EXP,), (P_QUERY_DATA,), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger) == [[False]]
    assert stub.calls == []


@pytest.mark.asyncio
async def test_evaluate_logs_once_with_pcgl_decisions(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger, log_output: LogCapture
):
    engine, _ = stub_engine({STUDY_A})
    await engine.evaluate((R_A_EXP, R_B_EXP), (P_DOWNLOAD_METADATA,), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    entries = [e for e in log_output.entries if e["event"] == "evaluate"]
    assert len(entries) == 1  # R_B_EXP (STUDY_B) is not allowed
    log_obj = entries[0]["positional_args"][0]
    assert log_obj["decisions"] == [[True], [False]]  # final decisions, after PCGL
    assert log_obj["pcgl_decisions"] == {STUDY_A: True, STUDY_B: False}
    assert log_obj["user"]["sub"] == sd.SUB


@pytest.mark.asyncio
async def test_determine_permissions_agrees_with_evaluate(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    # Study A: Bento query:data grant (gives download:metadata). Study B: PCGL-approved only.
    grants = (make_grant(1, sd.SUBJECT_DAVID, R_A, P_QUERY_DATA),)
    engine, stub = stub_engine({STUDY_B}, grants)

    for r in (R_A_EXP, R_B_EXP, R_A, R_A_PHENO, R_PROJECT):
        perms = await engine.determine_permissions(r, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
        res = await engine.evaluate((r,), ALL_DATA_PERMS, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
        assert [p in perms for p in ALL_DATA_PERMS] == res[0]

    stub.calls.clear()
    perms = await engine.determine_permissions(R_A_EXP, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert {P_QUERY_DATA, P_DOWNLOAD_METADATA} <= perms  # both from the Bento grant
    assert stub.calls == []  # nothing for PCGL to add

    perms = await engine.determine_permissions(R_B_EXP, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert P_DOWNLOAD_METADATA in perms  # from PCGL
    assert P_QUERY_DATA not in perms  # PCGL adds nothing else
    assert stub.calls == [[STUDY_B]]

    stub.calls.clear()
    assert P_DOWNLOAD_METADATA not in await engine.determine_permissions(R_A_EXP, None, None, plogger)
    assert stub.calls == []  # anonymous: no call


@pytest.mark.asyncio
async def test_determine_permissions_bento_grant_skips_pcgl(
    stub_engine: StubEngineFactory, plogger: structlog.stdlib.BoundLogger
):
    grants = (make_grant(1, sd.SUBJECT_DAVID, R_A, P_DOWNLOAD_METADATA),)
    engine, stub = stub_engine(set(), grants)
    assert P_DOWNLOAD_METADATA in await engine.determine_permissions(R_A_EXP, USER_TOKEN, sd.TEST_TOKEN_DATA, plogger)
    assert stub.calls == []


# --- pcgl_allowed HTTP behaviour (fake PCGL authz service) -------------------------------------------------------

# Builds a custom /allowed response from the requested study IDs
AllowedResponseFactory = Callable[[list[str]], web.Response]


class FakePcgl:
    """
    Fake server for pcgl-authz service endpoints. Simply stubbing PcglPolicyEngine.pcgl_allowed
    does not cover the HTTP error handling, so we use actual requests instead.

    Used to test:
    - Service token obtention/renewal with /service/{service_id}/verify
    - Delegated authz checks with /allowed (only allows STUDY_A by default)
    - Errors: timeouts, status code, bad responses, invalid token
    """

    def __init__(self) -> None:
        # Record requests to validate what the engine sent and how many calls were made.
        self.verify_requests: list[dict[str, Any]] = []
        self.allowed_requests: list[dict[str, Any]] = []

        # Stub config defaults
        self.verify_status: int = 200
        self.valid_service_tokens: set[str] | None = None  # None: accept any service token
        self.allowed_response: AllowedResponseFactory | None = None  # None: allow STUDY_A only
        self.delay: float = 0.0  # seconds to wait before answering /allowed
        self.url: str = ""  # set once the fake server is running

    async def verify(self, request: web.Request) -> web.Response:
        self.verify_requests.append({"service_id": request.match_info["service_id"], "body": await request.json()})
        if self.verify_status != 200:
            return web.Response(status=self.verify_status, text="nope")
        return web.json_response({"token": f"svc-token-{len(self.verify_requests)}"})

    async def allowed(self, request: web.Request) -> web.Response:

        body = await request.json()
        self.allowed_requests.append({"headers": dict(request.headers), "body": body})

        # Configurable delay for service token expiration tests
        if self.delay:
            await asyncio.sleep(self.delay)
        if (
            self.valid_service_tokens is not None
            and request.headers["X-Service-Token"] not in self.valid_service_tokens
        ):
            return web.Response(status=401, text="bad service token")

        if self.allowed_response is not None:
            return self.allowed_response(body["studies"])

        # Defaults to only allowing STUDY_A
        return web.json_response([s == STUDY_A for s in body["studies"]])


@pytest_asyncio.fixture
async def fake_pcgl() -> AsyncGenerator[FakePcgl, None]:
    fake = FakePcgl()
    pcgl_app = web.Application()
    pcgl_app.router.add_post("/service/{service_id}/verify", fake.verify)
    pcgl_app.router.add_post("/allowed", fake.allowed)
    server = TestServer(pcgl_app)
    await server.start_server()
    fake.url = str(server.make_url("/"))
    yield fake
    await server.close()


def _assert_no_secrets_logged(log_output: LogCapture) -> None:
    # Assert that no secret values are logged
    logged = repr(log_output.entries)
    assert USER_TOKEN not in logged
    assert SERVICE_SECRET not in logged
    assert "svc-token-" not in logged  # fake service token value prefix


@pytest.mark.asyncio
async def test_pcgl_allowed_request_shape(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger, log_output: LogCapture
):
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    res = await engine.pcgl_allowed(USER_TOKEN, [STUDY_A, STUDY_B, STUDY_A], plogger)
    assert res == {STUDY_A: True, STUDY_B: False}

    assert fake_pcgl.verify_requests == [{"service_id": SERVICE_ID, "body": {"service_uuid": SERVICE_SECRET}}]
    (req,) = fake_pcgl.allowed_requests
    assert req["headers"]["Authorization"] == f"Bearer {USER_TOKEN}"
    assert req["headers"]["X-Service-Id"] == SERVICE_ID
    assert req["headers"]["X-Service-Token"] == "svc-token-1"
    assert req["body"] == {"action": {"endpoint": "/export/study", "method": "GET"}, "studies": [STUDY_A, STUDY_B]}
    _assert_no_secrets_logged(log_output)


@pytest.mark.asyncio
async def test_pcgl_allowed_reuses_service_token(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    # Two consecutive calls must both work and share one service token.
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: True}
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: True}
    assert len(fake_pcgl.verify_requests) == 1
    assert len(fake_pcgl.allowed_requests) == 2


@pytest.mark.asyncio
async def test_pcgl_allowed_refreshes_expired_service_token(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger)
    assert len(fake_pcgl.verify_requests) == 1
    assert fake_pcgl.allowed_requests[0]["headers"]["X-Service-Token"] == "svc-token-1"

    # Force expired token before next pcgl_allowed call
    engine._service_token_expiry = datetime.now(UTC) - timedelta(seconds=1)
    await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger)

    # Check that token was renewed: verify requests increment and new svc token
    assert len(fake_pcgl.verify_requests) == 2
    assert fake_pcgl.allowed_requests[1]["headers"]["X-Service-Token"] == "svc-token-2"


@pytest.mark.asyncio
async def test_pcgl_allowed_retries_once_with_new_service_token(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger)  # caches svc-token-1

    fake_pcgl.valid_service_tokens = {"svc-token-2"}  # svc-token-1 revoked
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: True}
    assert len(fake_pcgl.verify_requests) == 2
    assert len(fake_pcgl.allowed_requests) == 3


@pytest.mark.asyncio
async def test_pcgl_allowed_no_retry_with_fresh_service_token(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    fake_pcgl.allowed_response = lambda _studies: web.Response(status=401, text="bad user token")
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: False}
    assert len(fake_pcgl.verify_requests) == 1
    assert len(fake_pcgl.allowed_requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        lambda studies: web.Response(status=500, text="boom"),
        lambda studies: web.json_response([True] * (len(studies) + 1)),  # wrong length
        lambda studies: web.json_response(["yes"] * len(studies)),  # not booleans
        lambda studies: web.json_response({"allowed": True}),  # not a list
        lambda studies: web.Response(status=200, text="not json"),
    ],
)
async def test_pcgl_allowed_bad_responses_deny(
    fake_pcgl: FakePcgl,
    idp_manager: BaseIdPManager,
    plogger: structlog.stdlib.BoundLogger,
    log_output: LogCapture,
    response: AllowedResponseFactory,
):
    fake_pcgl.allowed_response = response
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A, STUDY_B], plogger) == {STUDY_A: False, STUDY_B: False}
    assert any(e["log_level"] == "error" for e in log_output.entries)
    _assert_no_secrets_logged(log_output)


@pytest.mark.asyncio
async def test_pcgl_allowed_service_token_failure_denies(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger, log_output: LogCapture
):
    fake_pcgl.verify_status = 500
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: False}
    assert fake_pcgl.allowed_requests == []
    _assert_no_secrets_logged(log_output)


@pytest.mark.asyncio
async def test_pcgl_allowed_timeout_denies(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    fake_pcgl.delay = 1
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url, timeout=0.1)
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: False}


@pytest.mark.asyncio
async def test_pcgl_allowed_unreachable_denies(
    idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger, log_output: LogCapture
):
    engine = make_policy_engine(idp_manager, url="http://127.0.0.1:1")
    assert await engine.pcgl_allowed(USER_TOKEN, [STUDY_A], plogger) == {STUDY_A: False}
    _assert_no_secrets_logged(log_output)


@pytest.mark.asyncio
async def test_pcgl_allowed_no_token_no_request(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    assert await engine.pcgl_allowed(None, [STUDY_A], plogger) == {STUDY_A: False}
    assert await engine.pcgl_allowed(USER_TOKEN, [], plogger) == {}
    assert fake_pcgl.verify_requests == []
    assert fake_pcgl.allowed_requests == []


@pytest.mark.asyncio
async def test_evaluate_with_fake_pcgl(
    fake_pcgl: FakePcgl, idp_manager: BaseIdPManager, plogger: structlog.stdlib.BoundLogger
):
    engine = make_policy_engine(idp_manager, url=fake_pcgl.url)
    res = await engine.evaluate(
        (R_A_EXP, R_B_EXP, R_A), (P_DOWNLOAD_METADATA, P_QUERY_DATA), USER_TOKEN, sd.TEST_TOKEN_DATA, plogger
    )
    # STUDY_A and STUDY_B delegated check only makes one /allowed call
    assert res == [[True, False], [False, False], [False, False]]
    assert len(fake_pcgl.allowed_requests) == 1


# --- config + dependency -----------------------------------------------------------------------------------------

PCGL_SETTINGS: dict[str, Any] = {
    "policy_engine": "pcgl",
    "pcgl_authz_service_url": "https://pcgl.local",
    "pcgl_service_id": SERVICE_ID,
    "pcgl_service_secret": SERVICE_SECRET,
}


def test_config_pcgl_valid():
    c = Config(**PCGL_SETTINGS)
    assert c.pcgl_service_secret.get_secret_value() == SERVICE_SECRET
    assert SERVICE_SECRET not in repr(c)


@pytest.mark.parametrize(
    "overrides",
    [
        {"pcgl_authz_service_url": ""},
        {"pcgl_service_id": ""},
        {"pcgl_service_secret": ""},
        {"pcgl_authz_action_endpoint": ""},
        {"pcgl_service_token_lifespan": 0},
        {"pcgl_request_timeout": 0},
    ],
)
def test_config_pcgl_invalid(overrides: dict[str, Any]):
    with pytest.raises(ValidationError) as e:
        Config(**{**PCGL_SETTINGS, **overrides})
    assert SERVICE_SECRET not in str(e.value)


def test_config_bento_engine_needs_no_pcgl_settings():
    assert Config(policy_engine="bento").policy_engine == "bento"


def test_get_policy_engine_sync():
    # Built from a synchronous dependency (no running event loop) - must not create aiohttp objects.
    idp_manager = get_mock_idp_manager()
    provider = MemoryDataProvider()

    pe = get_policy_engine.__wrapped__(Config(**PCGL_SETTINGS, bento_debug=True), idp_manager, provider)
    assert isinstance(pe, PcglPolicyEngine)
    assert pe.pcgl_authz_url == "https://pcgl.local"
    assert not pe.verify_ssl
    assert pe.jwt_access_tokens

    pe = get_policy_engine.__wrapped__(Config(jwt_access_tokens=False), idp_manager, provider)
    assert type(pe) is BentoPolicyEngine
    assert not pe.jwt_access_tokens


# --- policy routers with the PCGL engine -------------------------------------------------------------------------


@pytest.fixture
def pcgl_router_stub(stub_engine: StubEngineFactory, test_client: TestClient) -> Generator[PcglStub, None, None]:
    engine, stub = stub_engine({STUDY_A})
    app.dependency_overrides[get_policy_engine] = lambda: engine
    yield stub
    app.dependency_overrides.pop(get_policy_engine, None)


def _res_json(*rs: ResourceModel) -> list[dict]:
    return [r.model_dump(mode="json", exclude_none=True) for r in rs]


# noinspection PyUnusedLocal
def test_policy_endpoints_with_pcgl(
    pcgl_router_stub: PcglStub, test_client: TestClient, auth_headers: dict[str, str], db_cleanup: None
):
    res = test_client.post(
        "/policy/evaluate",
        headers=auth_headers,
        json={"resources": _res_json(R_A_EXP, R_B_EXP, R_A), "permissions": [P_DOWNLOAD_METADATA, P_QUERY_DATA]},
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["result"] == [[True, False], [False, False], [False, False]]

    res = test_client.post(
        "/policy/evaluate_one",
        headers=auth_headers,
        json={"resource": _res_json(R_A_EXP)[0], "permission": P_DOWNLOAD_METADATA},
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["result"] is True

    res = test_client.post("/policy/permissions", headers=auth_headers, json={"resources": _res_json(R_A_EXP, R_A)})
    assert res.status_code == status.HTTP_200_OK
    assert P_DOWNLOAD_METADATA in res.json()["result"][0]
    assert P_DOWNLOAD_METADATA not in res.json()["result"][1]

    # anonymous: no PCGL access
    pcgl_router_stub.calls.clear()
    res = test_client.post(
        "/policy/evaluate", json={"resources": _res_json(R_A_EXP), "permissions": [P_DOWNLOAD_METADATA]}
    )
    assert res.json()["result"] == [[False]]
    assert pcgl_router_stub.calls == []
