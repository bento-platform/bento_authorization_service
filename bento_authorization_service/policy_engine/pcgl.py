from collections.abc import Sequence

from bento_lib.auth.permissions import P_DOWNLOAD_DATA, P_QUERY_DATA, Permission
from fastapi import status
from sentry_sdk.integrations import aiohttp
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


class PcglPolicyEngine(BentoPolicyEngine):
    """
    A policy engine which back-channels policy decisions to the PCGL authorization service, and falls back to the Bento
    engine if permissions do not map to the PCGL service.
    """

    PCGL_DELEGATED_PERMISSIONS = frozenset((P_QUERY_DATA, P_DOWNLOAD_DATA))

    def __init__(self, idp_manager: BaseIdPManager, provider: BaseDataProvider, pcgl_authz_url: str):
        super().__init__(idp_manager, provider)
        self.pcgl_authz_url = pcgl_authz_url.rstrip("/")

    async def _call_pcgl_authz(self, token: str | None, study_ids: tuple[str, ...], logger: BoundLogger) -> list[bool]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        async with (
            aiohttp.ClientSession(headers=headers) as session,
            # TODO: fill in endpoint
            session.post(
                f"{self.pcgl_authz_url}/allowed",
                json={"action": {"endpoint": "", "method": "GET"}, "studies": study_ids},
            ) as res,
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
        # TODO: implement me

        # query:data and download:data are determined by the PCGL authz service
        perms = (
            set(await super().determine_permissions(requested_resource, token, token_data, logger))
            - self.PCGL_DELEGATED_PERMISSIONS
        )

        # TODO: handle non-dataset resources
        if isinstance(requested_resource.root, ResourceSpecificModel) and (study_id := requested_resource.root.dataset):
            res = await self._call_pcgl_authz(token, (study_id,), logger)
            if res[0]:  # first element, corresponding to requested study
                # Having "access" to a study in the PCGL context means full data access:
                #  querying + downloading files, plus derived permissions
                perms.update(self.PCGL_DELEGATED_PERMISSIONS)

        return frozenset(perms)

    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> tuple[tuple[bool, ...], ...]:
        # TODO: implement me
        return await super().evaluate(resources, permissions, token, token_data, logger)
