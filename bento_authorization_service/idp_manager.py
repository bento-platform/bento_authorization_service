import aiohttp
import jwt

from abc import ABC, abstractmethod
from datetime import datetime
from fastapi import Depends
from functools import lru_cache
from structlog.stdlib import BoundLogger
from typing import Annotated, Optional

from .config import ConfigDependency
from .logger import LoggerDependency

__all__ = [
    "IdPManagerBadAlgorithmError",
    "UninitializedIdPManagerError",
    "BaseIdPManager",
    "IdPManager",
    "get_idp_manager",
    "IdPManagerDependency",
]


class IdPManagerError(Exception):
    pass


class UninitializedIdPManagerError(IdPManagerError):
    pass


class IdPManagerBadAlgorithmError(IdPManagerError):
    pass


class BaseIdPManager(ABC):
    def __init__(
        self,
        logger: BoundLogger,
        openid_config_url: str,
        audience: str,
        disabled_token_signing_algorithms: frozenset[str],
        debug: bool,
    ):
        self._logger: BoundLogger = logger

        self._openid_config_url: str = openid_config_url
        self._audience: str = audience
        self._disabled_token_signing_algorithms: frozenset[str] = disabled_token_signing_algorithms
        self._debug: bool = debug

        self._initialized: bool = False

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def debug(self) -> bool:
        return self._debug

    @abstractmethod
    def get_supported_token_signing_algs(self) -> frozenset[str]:  # pragma: no cover
        pass

    def get_permitted_token_signing_algs(self) -> frozenset[str]:
        # Assume we have the same set of signing algorithms for access tokens as ID tokens
        return self.get_supported_token_signing_algs() - self._disabled_token_signing_algorithms

    def _verify_token_and_decode(
        self,
        token: str,
        signing_key: jwt.PyJWK | str,
    ) -> dict:
        permitted_algs = self.get_permitted_token_signing_algs()

        # Check the token matches permitted algorithms
        self.check_token_signing_alg(jwt.get_unverified_header(token), permitted_algs)

        # Return the decoded & verified JWT
        return jwt.decode(
            token,
            signing_key if isinstance(signing_key, str) else signing_key.key,
            audience=self.audience,
            algorithms=permitted_algs,
        )

    @staticmethod
    def check_token_signing_alg(token_header: dict, permitted_algs: frozenset[str]):
        if (alg := token_header.get("alg")) is None or alg not in permitted_algs:
            raise IdPManagerBadAlgorithmError("Token signing algorithm not permitted")

    @abstractmethod
    async def initialize(self):  # pragma: no cover
        pass

    @property
    def initialized(self) -> bool:
        return self._initialized

    @abstractmethod
    async def decode(self, token: str) -> dict:  # pragma: no cover
        pass


JWKS_EXPIRY_TIME = 60  # seconds
OPENID_CONFIGURATION_EXPIRY_TIME = 3600  # seconds


class IdPManager(BaseIdPManager):
    def __init__(
        self,
        logger: BoundLogger,
        openid_config_url: str,
        audience: str,
        disabled_token_signing_algorithms: frozenset[str],
        debug: bool = False,
    ):
        super().__init__(logger, openid_config_url, audience, disabled_token_signing_algorithms, debug)

        self._openid_config_data: Optional[dict] = None
        self._openid_config_data_last_fetched: Optional[datetime] = None

        self._jwks: tuple[jwt.PyJWK, ...] = ()
        self._jwks_last_fetched = 0

    async def fetch_openid_config_if_needed(self):
        lf = self._openid_config_data_last_fetched
        time_since_last_fetched = -1
        if not lf or (time_since_last_fetched := (datetime.now() - lf).seconds) > OPENID_CONFIGURATION_EXPIRY_TIME:
            logger = self._logger.bind(time_since_last_fetched=time_since_last_fetched)
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=not self.debug)) as session:
                    async with session.get(self._openid_config_url, raise_for_status=True) as res:
                        self._openid_config_data = await res.json()
                        self._openid_config_data_last_fetched = datetime.now()
                        await logger.adebug("fetched OpenID configuration data", status=res.status)
            except aiohttp.ClientError as e:
                await logger.aexception("error fetching OpenID configuration data", exc_info=e)
                # Do not re-raise here; if it's a transient error, we can re-use old configuration data

    async def fetch_jwks_if_needed(self):
        await self.fetch_openid_config_if_needed()

        if not self._openid_config_data:
            raise IdPManagerError("fetch_jwks: missing OpenID configuration data")

        if ((now := datetime.now().timestamp()) - self._jwks_last_fetched) > JWKS_EXPIRY_TIME:
            # Manually do JWK signing key fetching. This way, we can turn off SSL verification in debug mode.
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=not self.debug)) as session:
                async with session.get(self._openid_config_data["jwks_uri"]) as res:
                    self._jwks = tuple(
                        k
                        for k in jwt.PyJWKSet.from_dict(await res.json()).keys
                        if k.public_key_use in ("sig", None) and k.key_id
                    )
                    self._jwks_last_fetched = now

    def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK | None:
        header = jwt.get_unverified_header(token)
        return next((k for k in self._jwks if k.key_id == header["kid"]), None)

    async def initialize(self):
        try:
            await self.fetch_openid_config_if_needed()
            await self.fetch_jwks_if_needed()
            self._initialized = True
        except Exception as e:
            await self._logger.aexception("could not initialize IdPManager: encountered exception", exc_info=e)
            self._initialized = False

    def get_supported_token_signing_algs(self) -> frozenset[str]:
        return frozenset(self._openid_config_data["id_token_signing_alg_values_supported"])

    async def decode(self, token: str) -> dict:
        await self.fetch_jwks_if_needed()  # Refresh well-known key set if it has expired or not yet been fetched

        # This relies on access tokens following RFC9068, rather than using the introspection endpoint.

        if not self._initialized:  # Initialize the IdPManager lazily on first decode request
            await self.initialize()
            if not self._initialized:  # Initialization failed
                raise UninitializedIdPManagerError("IdpManager initialization failed")

        if not self._jwks_last_fetched:
            raise UninitializedIdPManagerError("JWKS not fetched")

        if (sk := self.get_signing_key_from_jwt(token)) is not None:
            # Obtain the IdP's supported token signing algorithms & pass them to the verify function
            return self._verify_token_and_decode(token, sk)

        raise IdPManagerError("Could not get signing key for token")


@lru_cache()
def get_idp_manager(config: ConfigDependency, logger: LoggerDependency) -> BaseIdPManager:
    return IdPManager(
        logger,
        config.openid_config_url,
        config.token_audience,
        config.disabled_token_signing_algorithms,
        config.bento_debug,
    )


IdPManagerDependency = Annotated[BaseIdPManager, Depends(get_idp_manager)]
