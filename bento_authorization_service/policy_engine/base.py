from abc import ABC, abstractmethod
from collections.abc import Sequence

from bento_lib.auth.permissions import Permission
from structlog.stdlib import BoundLogger

from bento_authorization_service.models import ResourceModel

from .token_data import TokenData

__all__ = ["PolicyEngine"]


class PolicyEngine(ABC):
    """
    Common interface for Bento and PCGL policy engines, defining public permissions-evaluation functions.
    """

    @abstractmethod
    async def determine_permissions(
        self, requested_resource: ResourceModel, token: str | None, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]: ...

    @abstractmethod
    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> tuple[tuple[bool, ...], ...]: ...
