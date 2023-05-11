import aiohttp
import datetime
import jwt

from abc import ABC, abstractmethod
from datetime import datetime
from fastapi import Depends
from functools import lru_cache
from typing import Annotated, Optional

from .config import ConfigDependency
from .logger import logger

__all__ = [
    "UninitializedIdPManagerError",
    "BaseIdPManager",
    "IdPManager",
    "get_idp_manager",
    "IdPManagerDependency",
]


class UninitializedIdPManagerError(Exception):
    pass


class BaseIdPManager(ABC):
    def __init__(self, openid_config_url: str, debug: bool):
        self._openid_config_url: str = openid_config_url
        self._debug = debug

    @property
    def debug(self) -> bool:
        return self._debug

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


JWKS_EXPIRY_TIME = 60  # seconds


class IdPManager(BaseIdPManager):
    def __init__(self, openid_config_url: str, debug: bool = False):
        super().__init__(openid_config_url, debug)

        self._openid_config_data: Optional[dict] = None
        self._openid_config_data_last_fetched: Optional[datetime.datetime] = None

        self._jwks: tuple[jwt.PyJWK, ...] = ()
        self._jwks_last_fetched = 0

        self._initialized: bool = False

    async def fetch_well_known_data(self):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=not self.debug)) as session:
            async with session.get(self._openid_config_url) as res:
                self._openid_config_data = await res.json()
                self._openid_config_data_last_fetched = datetime.datetime.now()

    async def fetch_jwks_if_needed(self):
        if not self._openid_config_data:
            logger.error("fetch_jwks: Missing OpenID configuration data")

        if ((now := datetime.now().timestamp()) - self._jwks_last_fetched) > JWKS_EXPIRY_TIME:
            # Manually do JWK signing key fetching. This way, we can turn off SSL verification in debug mode.
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=not self.debug)) as session:
                async with session.get(self._openid_config_data["jwks_uri"]) as res:
                    self._jwks = tuple(
                        k for k in jwt.PyJWKSet.from_dict(await res.json()).keys
                        if k.public_key_use in ("sig", None) and k.key_id
                    )
                    self._jwks_last_fetched = now

    async def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK | None:
        header = jwt.get_unverified_header(token)
        return next((k for k in self._jwks if k.key_id == header["kid"]), None)

    async def initialize(self):
        try:
            await self.fetch_well_known_data()
            if self._openid_config_data_last_fetched:
                await self.fetch_jwks_if_needed()
            self._initialized = True
        except Exception as e:
            logger.critical(f"Could not initialize IdPManager: encountered exception '{repr(e)}'")
            self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    async def decode(self, token: str) -> dict:
        await self.fetch_jwks_if_needed()  # Refresh well-known key set if it has expired or not yet been fetched

        # This relies on access tokens following RFC9068, rather than using the introspection endpoint.

        if not self._initialized:  # Initialize the IdPManager lazily on first decode request
            await self.initialize()
            if not self._initialized:  # Initialization failed
                raise UninitializedIdPManagerError("IdpManager initialization failed")
        if not self._jwks_last_fetched:
            raise UninitializedIdPManagerError("JWKS not fetched yet")

        sk = self.get_signing_key_from_jwt(token)

        if sk is None:
            raise Exception("Could not get signing key for token")  # TODO: IdPManagerError

        # Assume we have the same set of signing algorithms for access tokens as ID tokens
        return jwt.decode(token, sk, algorithms=self._openid_config_data["id_token_signing_alg_values_supported"])


@lru_cache()
def get_idp_manager(config: ConfigDependency) -> BaseIdPManager:
    return IdPManager(config.openid_config_url, config.bento_debug)


IdPManagerDependency = Annotated[BaseIdPManager, Depends(get_idp_manager)]
