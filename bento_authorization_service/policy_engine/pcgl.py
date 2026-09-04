from bento_lib.auth.permissions import Permission
from structlog.stdlib import BoundLogger

from ..models import ResourceModel
from .base import PolicyEngine
from .token_data import TokenData

__all__ = ["PcglPolicyEngine"]


class PcglPolicyEngine(PolicyEngine):
    """
    A policy engine which back-channels policy decisions to the PCGL authorization service.
    """

    def __init__(self, authz_url: str):
        self.authz_url = authz_url

    async def determine_permissions(
        self, requested_resource: ResourceModel, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]:
        # TODO: implement me
        raise NotImplementedError()

    async def evaluate(
        self,
        resources: list[ResourceModel] | tuple[ResourceModel, ...],
        permissions: list[Permission] | tuple[Permission, ...],
        token: str | TokenData | None,
        logger: BoundLogger,
    ) -> tuple[tuple[bool, ...], ...]:
        # TODO: implement me
        raise NotImplementedError()
