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
    async def determine_permissions_bulk(
        self,
        resources: Sequence[ResourceModel],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[frozenset[Permission]]:
        """
        Given a token (or None if anonymous) and some resources, return the permissions the token has on each resource
        (one frozen set per resource, in the same order).
        """

    async def determine_permissions(
        self, requested_resource: ResourceModel, token: str | None, token_data: TokenData | None, logger: BoundLogger
    ) -> frozenset[Permission]:
        """
        Single-resource version of determine_permissions_bulk.
        """
        return (await self.determine_permissions_bulk((requested_resource,), token, token_data, logger))[0]

    @abstractmethod
    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[list[bool]]: ...
