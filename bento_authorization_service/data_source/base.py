import asyncio
from abc import ABC, abstractmethod

from bento_authorization_service.models import StoredGrantModel, StoredGroupModel


class BaseDataSource(ABC):
    @abstractmethod
    async def get_grant(self, id_: int) -> StoredGrantModel | None: ...

    @abstractmethod
    async def get_grants(self) -> tuple[StoredGrantModel, ...]: ...

    @abstractmethod
    async def get_group(self, id_: int) -> StoredGroupModel | None: ...

    @abstractmethod
    async def get_groups(self) -> tuple[StoredGroupModel, ...]: ...

    async def get_groups_dict(self) -> dict[int, StoredGroupModel]:
        return {g.id: g for g in (await self.get_groups())}

    async def get_grants_and_groups_dict(self) -> tuple[tuple[StoredGrantModel, ...], dict[int, StoredGroupModel]]:
        return await asyncio.gather(self.get_grants(), self.get_groups_dict())
