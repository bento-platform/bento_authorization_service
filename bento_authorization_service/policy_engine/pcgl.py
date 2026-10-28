from collections.abc import Sequence

from bento_lib.auth.permissions import Permission
from structlog.stdlib import BoundLogger

from ..data_provider.base import BaseDataProvider
from ..idp_manager import BaseIdPManager
from ..models import ResourceModel
from .evaluation import BentoPolicyEngine
from .token_data import TokenData

__all__ = ["PcglPolicyEngine"]


class PcglPolicyEngine(BentoPolicyEngine):
    """
    A policy engine which back-channels policy decisions to the PCGL authorization service, and falls back to the Bento
    engine if permissions do not map to the PCGL service.
    """

    def __init__(self, idp_manager: BaseIdPManager, provider: BaseDataProvider, pcgl_authz_url: str):
        super().__init__(idp_manager, provider)
        self.pcgl_authz_url = pcgl_authz_url

    async def determine_permissions(
        self, requested_resource: ResourceModel, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]:
        # TODO: implement me
        return await super().determine_permissions(requested_resource, token_data, logger)

    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | TokenData | None,
        logger: BoundLogger,
    ) -> tuple[tuple[bool, ...], ...]:
        # TODO: implement me
        return await super().evaluate(resources, permissions, token, logger)
