from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import aiohttp
from bento_lib.auth.permissions import P_DOWNLOAD_DATA, P_QUERY_DATA, Permission
from fastapi import status
from structlog.stdlib import BoundLogger

from ..data_provider.base import BaseDataProvider
from ..idp_manager import BaseIdPManager
from ..models import ResourceModel, ResourceSpecificModel
from .evaluation import BentoPolicyEngine
from .token_data import TokenData

__all__ = ["PcglPolicyEngine"]


class PcglAuthzError(Exception):
    """
    Wrapper exception class for non-200 responses from the PCGL authz service.
    """


def _resource_dataset_id(resource: ResourceModel) -> str | None:
    """
    If the resource is a dataset, extract the dataset ID. Otherwise, return None since we do not have a dataset
    (PCGL study) that can be checked.
    """
    if isinstance(resource.root, ResourceSpecificModel) and (dataset_id := resource.root.dataset):
        return dataset_id
    return None


class PcglPolicyEngine(BentoPolicyEngine):
    """
    A policy engine which back-channels policy decisions to the PCGL authorization service, and falls back to the Bento
    engine if permissions do not map to the PCGL service.
    """

    PCGL_DELEGATED_PERMISSIONS = frozenset((P_QUERY_DATA, P_DOWNLOAD_DATA))

    def __init__(
        self,
        idp_manager: BaseIdPManager,
        provider: BaseDataProvider,
        pcgl_authz_url: str,
        pcgl_service_id: str,
        pcgl_service_secret: str,
        pcgl_service_token_lifespan: int,
        debug: bool = False,
    ):
        super().__init__(idp_manager, provider)

        self.debug = debug

        self.pcgl_authz_url = pcgl_authz_url.rstrip("/")
        self.pcgl_service_id = pcgl_service_id
        self.pcgl_service_secret = pcgl_service_secret
        self.pcgl_service_token_lifespan = pcgl_service_token_lifespan

        self._service_token: str | None = None
        self._service_token_expiry: datetime = datetime.now(UTC) - timedelta(seconds=1)

        self._tcp_connector = aiohttp.TCPConnector(verify_ssl=not self.debug)

    @property
    def pcgl_all_delegated_permissions(self) -> frozenset[Permission]:
        s = set(self.PCGL_DELEGATED_PERMISSIONS)
        for p in self.PCGL_DELEGATED_PERMISSIONS:
            s.update(p.gives)
        return frozenset(s)

    async def _get_pcgl_authz_request_token(self, logger: BoundLogger) -> str:
        now = datetime.now(UTC)

        if self._service_token and self._service_token_expiry > now:
            return self._service_token

        # Otherwise, we don't have an extant token to use. Request a new one.

        payload = {"service_uuid": self.pcgl_service_secret}

        async with (
            aiohttp.ClientSession(connector=self._tcp_connector) as session,
            session.post(f"{self.pcgl_authz_url}/service/{self.pcgl_service_id}/verify", json=payload) as res,
        ):
            if res.status != status.HTTP_200_OK:
                event = "could not get PCGL service token"
                await logger.acritical(event, status=res.status, response_body=await res.content.read())
                raise PcglAuthzError(event)
            new_token = (await res.json())["token"]

        self._service_token = new_token
        self._service_token_expiry = datetime.now(UTC) + timedelta(seconds=self.pcgl_service_token_lifespan)
        return new_token

    async def _call_pcgl_authz(self, token: str | None, study_ids: tuple[str, ...], logger: BoundLogger) -> list[bool]:
        if not token:
            return [False] * len(study_ids)  # PCGL authz has no concept of anonymous access; always return a "no"

        headers = {
            "Authorization": f"Bearer {token}",
            "X-Service-Id": self.pcgl_service_id,
            "X-Service-Token": await self._get_pcgl_authz_request_token(logger),
        }

        # TODO: fill in endpoint properly
        payload = {
            "action": {
                "endpoint": "/export/study",  # TODO
                "method": "GET",
            },
            "studies": study_ids,
        }

        async with (
            aiohttp.ClientSession(connector=self._tcp_connector, headers=headers) as session,
            session.post(f"{self.pcgl_authz_url}/allowed", json=payload) as res,
        ):
            if res.status != status.HTTP_200_OK:
                await logger.aerror(
                    "got non-200 response from PCGL authorization service",
                    status=res.status,
                    response_body=await res.content.read(),
                )
                raise PcglAuthzError()

            return await res.json()  # array of boolean

    async def determine_permissions(
        self, requested_resource: ResourceModel, token: str | None, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]:
        # query:data and download:data are determined by the PCGL authz service
        # - we do NOT subtract *derived* ("gives") permissions, since counts/Boolean access could be enabled by
        #   Bento-only grants.
        perms = (
            set(await super().determine_permissions(requested_resource, token, token_data, logger))
            - self.PCGL_DELEGATED_PERMISSIONS
        )

        # TODO: handle non-dataset resources?
        if study_id := _resource_dataset_id(requested_resource):
            res = await self._call_pcgl_authz(token, (study_id,), logger)
            if res[0]:  # first element, corresponding to requested study
                # Having "access" to a study in the PCGL context means full data access:
                #  querying + downloading files, plus derived permissions
                perms.update(self.pcgl_all_delegated_permissions)

        return frozenset(perms)

    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[list[bool]]:
        # First, evaluate permissions matrix using just our local grants. We will then mutate this matrix based on data
        # from the PCGL authz service.
        bento_res = await super().evaluate(resources, permissions, token, token_data, logger)

        # Partition the passed resources into:
        #  - the resources we are evaluating that are checkable against PCGL authz (i.e., datasets at the moment)
        #  - the resources we cannot evaluate using PCGL authz (whole-node or projects)
        pcgl_checkable_studies: list[tuple[int, str]] = []
        non_checkable_resource_indices: list[int] = []
        for i, r in enumerate(resources):
            if study_id := _resource_dataset_id(r):
                pcgl_checkable_studies.append((i, study_id))
            else:
                non_checkable_resource_indices.append(i)

        # Set of directly-delegated permission indices in the matrix
        delegated_perm_indices_direct_set: set[int] = {
            permissions.index(p) for p in self.PCGL_DELEGATED_PERMISSIONS if p in permissions
        }

        # Set of directly-delegated + derived permission indices in the matrix
        delegated_perm_indices_full_set: set[int] = {
            permissions.index(p) for p in self.pcgl_all_delegated_permissions if p in permissions
        }

        # Set all PCGL-delegated permissions to the result
        if delegated_perm_indices_full_set and pcgl_checkable_studies:
            res = await self._call_pcgl_authz(
                token, tuple(study_id for (_, study_id) in pcgl_checkable_studies), logger
            )
            for (i, s), r in zip(pcgl_checkable_studies, res):
                for j in delegated_perm_indices_full_set:
                    # TODO: if True, grant in full set; if false, grant in direct set
                    bento_res[i][j] = res[i]

        # Clear all PCGL-delegated permissions on non-checkable resources
        if non_checkable_resource_indices:
            for ri in non_checkable_resource_indices:
                for p in delegated_perm_indices_direct_set:
                    bento_res[ri][p] = False

        return bento_res
