import aiohttp
import datetime
import jwt

from abc import ABC, abstractmethod
from fastapi import Depends
from functools import lru_cache
from typing import Annotated, Optional

from .config import ConfigDependency
from .logger import logger

__all__ = [
    "IdPManagerBadAlgorithmError",
    "UninitializedIdPManagerError",
    "BaseIdPManager",
    "IdPManager",
    "get_idp_manager",
    "IdPManagerDependency",
    "check_token_signing_alg"
]


class IdPManagerError(Exception):
    pass


class UninitializedIdPManagerError(IdPManagerError):
    pass


class IdPManagerBadAlgorithmError(IdPManagerError):
    pass


class BaseIdPManager(ABC):

    def __init__(self, oidc_well_known_url: str):
        self._oidc_well_known_url: str = oidc_well_known_url

    @abstractmethod
    async def initialize(self):  # pragma: no cover
        pass

    @property
    @abstractmethod
    def initialized(self) -> bool:  # pragma: no cover
        pass

    @abstractmethod
    async def decode(self, token: str) -> dict:  # pragma: no cover
        pass


class IdPManager(BaseIdPManager):

    def __init__(self, oidc_well_known_url: str):
        super().__init__(oidc_well_known_url)

        self._oidc_well_known_data: Optional[dict] = None
        self._oidc_well_known_data_last_fetched: Optional[datetime.datetime] = None

        self._jwks_client: Optional[jwt.PyJWKClient] = None

        self._initialized: bool = False

    async def fetch_well_known_data(self):
        async with aiohttp.ClientSession() as session:
            async with session.get(self._oidc_well_known_url) as res:
                self._oidc_well_known_data = await res.json()
                self._oidc_well_known_data_last_fetched = datetime.datetime.now()

    def set_up_jwks_client(self):
        self._jwks_client = jwt.PyJWKClient(self._oidc_well_known_data["jwks_uri"])

    async def initialize(self):
        try:
            await self.fetch_well_known_data()
            if self._oidc_well_known_data_last_fetched:
                self.set_up_jwks_client()
            self._initialized = True
        except Exception as e:
            logger.critical(f"Could not initialize IdPManager: encountered exception '{repr(e)}'")
            self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    async def decode(self, token: str) -> dict:
        # This relies on access tokens following RFC9068, rather than using the introspection endpoint.

        if not self._initialized:  # Initialize the IdPManager lazily on first decode request
            await self.initialize()
            if not self._initialized:  # Initialization failed
                raise UninitializedIdPManagerError("IdpManager initialization failed")
        if not self._jwks_client:
            raise UninitializedIdPManagerError("Missing JWKS Manager")

        sk = self._jwks_client.get_signing_key_from_jwt(token)

        # Assume we have the same set of signing algorithms for access tokens as ID tokens
        decoded_token = jwt.decode(token, sk, algorithms=self._oidc_well_known_data["id_token_signing_alg_values_supported"])

        # Check if the algorithm used to sign the token is acceptable
        check_token_signing_alg(decoded_token, config.permitted_token_algorithms)

        return decoded_token


def check_token_signing_alg(decoded_token: dict, permitted_token_algorithms: frozenset):
    if (decoded_token.get("alg") is None or 
        decoded_token.get("alg") not in permitted_token_algorithms) :
        raise IdPManagerBadAlgorithmError("ID token signing algorithm not permitted")


@lru_cache()
def get_idp_manager(config: ConfigDependency) -> BaseIdPManager:
    return IdPManager(config.openid_well_known_url)


IdPManagerDependency = Annotated[BaseIdPManager, Depends(get_idp_manager)]
