from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
from bento_lib.auth.permissions import P_DOWNLOAD_METADATA, Permission
from fastapi import status
from pydantic import SecretStr
from structlog.stdlib import BoundLogger

from ..data_provider.base import BaseDataProvider
from ..idp_manager import BaseIdPManager
from ..models import ResourceModel, ResourceSpecificModel
from .evaluation import BentoPolicyEngine
from .token_data import TokenData

__all__ = ["PcglPolicyEngine"]


class PcglAuthzError(Exception):
    """
    Internal exception for failed calls to the PCGL authz service. Never escapes PcglPolicyEngine.pcgl_allowed.
    """


class PcglPolicyEngine(BentoPolicyEngine):
    """
    A policy engine which adds decisions from the PCGL authorization service on top of Bento grants.

    PCGL can only ADD the delegated permissions, on resources which map to a PCGL study (a Bento dataset whose ID is
    the PCGL study ID, narrowed to a delegated data type). Every other decision comes from Bento grants, and PCGL never
    removes a permission granted by Bento.
    """

    # The only permissions the PCGL authz service can grant:
    PCGL_DELEGATED_PERMISSIONS: frozenset[Permission] = frozenset({P_DOWNLOAD_METADATA})
    # ... plus what they give (nothing, as of writing):
    PCGL_GRANTED_PERMISSIONS: frozenset[Permission] = frozenset(
        {*PCGL_DELEGATED_PERMISSIONS, *(g for p in PCGL_DELEGATED_PERMISSIONS for g in p.gives)}
    )
    # PCGL authz decides per study, not per data type, so we only delegate for experiment data (file manifests).
    # To be revisited once the PCGL authz service supports data type-level decisions.
    PCGL_DELEGATED_DATA_TYPES: frozenset[str] = frozenset({"experiment"})

    def __init__(
        self,
        idp_manager: BaseIdPManager,
        provider: BaseDataProvider,
        *,
        jwt_access_tokens: bool = True,
        pcgl_authz_url: str,
        pcgl_service_id: str,
        pcgl_service_secret: SecretStr,
        pcgl_service_token_lifespan: int,
        pcgl_action_endpoint: str,
        pcgl_action_method: str,
        pcgl_request_timeout: float,
        verify_ssl: bool = True,
    ):
        super().__init__(idp_manager, provider, jwt_access_tokens=jwt_access_tokens)

        self.pcgl_authz_url = pcgl_authz_url.rstrip("/")
        self.pcgl_service_id = pcgl_service_id
        self._pcgl_service_secret = pcgl_service_secret
        self.pcgl_service_token_lifespan = pcgl_service_token_lifespan
        self.pcgl_action_endpoint = pcgl_action_endpoint
        self.pcgl_action_method = pcgl_action_method
        self.pcgl_request_timeout = pcgl_request_timeout
        self.verify_ssl = verify_ssl

        self._service_token: str | None = None
        self._service_token_expiry: datetime = datetime.now(UTC) - timedelta(seconds=1)

    @classmethod
    def _pcgl_study_id(cls, resource: ResourceModel) -> str | None:
        """
        If the resource can be checked against the PCGL authz service (a dataset narrowed to a delegated data type),
        return the dataset ID, which is the PCGL study ID. Otherwise, return None.
        """
        r = resource.root
        if isinstance(r, ResourceSpecificModel) and r.dataset and r.data_type in cls.PCGL_DELEGATED_DATA_TYPES:
            return r.dataset
        return None

    def _clear_service_token(self) -> None:
        self._service_token = None
        self._service_token_expiry = datetime.now(UTC) - timedelta(seconds=1)

    async def _get_service_token(self, session: aiohttp.ClientSession, logger: BoundLogger) -> tuple[str, bool]:
        """
        Get a PCGL service token, from the cache if still valid. Returns (token, whether it was freshly fetched).
        """
        if self._service_token and self._service_token_expiry > datetime.now(UTC):
            return self._service_token, False

        async with session.post(
            f"{self.pcgl_authz_url}/service/{self.pcgl_service_id}/verify",
            json={"service_uuid": self._pcgl_service_secret.get_secret_value()},
            ssl=self.verify_ssl,
        ) as res:
            if res.status != status.HTTP_200_OK:
                await logger.aerror(
                    "could not get PCGL service token",
                    status=res.status,
                    response_body=await res.text(),
                )
                raise PcglAuthzError("could not get PCGL service token")
            new_token = (await res.json())["token"]

        if not isinstance(new_token, str) or not new_token:
            raise PcglAuthzError("PCGL service token response did not contain a token")

        self._service_token = new_token
        self._service_token_expiry = datetime.now(UTC) + timedelta(seconds=self.pcgl_service_token_lifespan)
        return new_token, True

    async def _post_allowed(
        self, session: aiohttp.ClientSession, token: str, study_ids: list[str], logger: BoundLogger
    ) -> tuple[int, Any, bool]:
        """
        Call the PCGL /allowed endpoint. Returns (status, body (parsed JSON if 200, else text), whether the service
        token used was freshly fetched).
        """
        service_token, fresh = await self._get_service_token(session, logger)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Service-Id": self.pcgl_service_id,
            "X-Service-Token": service_token,
        }
        payload = {
            "action": {"endpoint": self.pcgl_action_endpoint, "method": self.pcgl_action_method},
            "studies": study_ids,
        }
        async with session.post(
            f"{self.pcgl_authz_url}/allowed", json=payload, headers=headers, ssl=self.verify_ssl
        ) as res:
            if res.status == status.HTTP_200_OK:
                return res.status, await res.json(), fresh
            return res.status, await res.text(), fresh

    async def pcgl_allowed(self, token: str | None, study_ids: Sequence[str], logger: BoundLogger) -> dict[str, bool]:
        """
        Ask the PCGL authz service whether the token bearer has access to each study. Never raises: any problem
        (no token, PCGL error, unexpected response, timeout) gives False for every study.
        """
        ids = list(dict.fromkeys(study_ids))  # de-duplicate, keep order
        denied = dict.fromkeys(ids, False)

        if not token or not ids:
            return denied  # PCGL authz has no concept of anonymous access, so default to deny.

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.pcgl_request_timeout)) as session:
                res_status, body, fresh = await self._post_allowed(session, token, ids, logger)

                if res_status in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN) and not fresh:
                    # Cached service token may have been revoked/expired early, get a new one and retry once.
                    self._clear_service_token()
                    res_status, body, _ = await self._post_allowed(session, token, ids, logger)

            if res_status != status.HTTP_200_OK:
                await logger.aerror(
                    "got non-200 response from PCGL authz service",
                    status=res_status,
                    response_body=str(body),
                )
                return denied

            if not isinstance(body, list) or len(body) != len(ids) or not all(isinstance(b, bool) for b in body):
                await logger.aerror(
                    "got unexpected response from PCGL authz service; expected a list of booleans, one per study",
                    n_studies=len(ids),
                    response_body=str(body),
                )
                return denied

            return dict(zip(ids, body, strict=True))

        except Exception as e:  # noqa: BLE001 - PCGL problems must never break Bento authz; deny instead
            # No exc_info: JSON log tracebacks include frame locals, which would leak the user/service tokens.
            await logger.aerror(
                "error while calling PCGL authz service",
                error_type=type(e).__name__,
                error=str(e),
                n_studies=len(ids),
            )
            return denied

    async def determine_permissions(
        self, requested_resource: ResourceModel, token: str | None, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]:
        bento_perms = await super().determine_permissions(requested_resource, token, token_data, logger)
        study_id = self._pcgl_study_id(requested_resource)

        # Only call PCGL if it could add something on this resource, skip when:
        # - anonymous
        # - no study_id
        # - PCGL permissions are a subset of BentoPolicyEngine perms
        if not token or study_id is None or self.PCGL_GRANTED_PERMISSIONS <= bento_perms:
            return bento_perms

        if (await self.pcgl_allowed(token, (study_id,), logger))[study_id]:
            # Union of BentoPolicyEngine and PCGL granted permissions
            return bento_perms | self.PCGL_GRANTED_PERMISSIONS
        return bento_perms

    def _pcgl_pending_cells(
        self, resources: Sequence[ResourceModel], permissions: Sequence[Permission], matrix: list[list[bool]]
    ) -> list[tuple[int, int, str]]:
        """
        Find the cells of an evaluation matrix that PCGL could still flip to True, as (row, column, study ID):
        a permission PCGL can grant, denied by Bento grants, on a resource which maps to a PCGL study.
        """
        pending_cells: list[tuple[int, int, str]] = []
        for row, resource in enumerate(resources):
            study_id = self._pcgl_study_id(resource)
            if study_id is None:
                continue  # not a PCGL study resource: Bento grants only
            for column, permission in enumerate(permissions):
                if permission in self.PCGL_GRANTED_PERMISSIONS and not matrix[row][column]:
                    pending_cells.append((row, column, study_id))
        return pending_cells

    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[list[bool]]:
        resolved_token_data = await self._resolve_token_data(token, token_data)

        # First, evaluate the matrix using just Bento grants. PCGL decisions can then only flip cells to True.
        matrix = await self._evaluate_matrix(resources, permissions, resolved_token_data, logger)

        # Cells PCGL could still flip to True. PCGL has no anonymous access, so there are none without a token.
        pending_cells = self._pcgl_pending_cells(resources, permissions, matrix) if token else []

        pcgl_decisions: dict[str, bool] = {}
        if pending_cells:
            # One call for all the studies involved (unique, in order of first appearance)
            study_ids = list(dict.fromkeys(study_id for _, _, study_id in pending_cells))
            pcgl_decisions = await self.pcgl_allowed(token, study_ids, logger)
            for row, column, study_id in pending_cells:
                if pcgl_decisions.get(study_id):
                    matrix[row][column] = True

        extra = {"pcgl_decisions": pcgl_decisions} if pending_cells else {}
        await self._log_evaluation(logger, resolved_token_data, resources, permissions, matrix, **extra)

        return matrix
