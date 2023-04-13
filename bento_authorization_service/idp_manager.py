import aiohttp
import datetime
import jwt

from typing import Optional

from .config import config

__all__ = [
    "UninitializedIdPManagerError",
    "IdPManager",
    "idp_manager",
]


class UninitializedIdPManagerError(Exception):
    pass


class IdPManager:

    def __init__(self, oidc_well_known_url: str):
        self._oidc_well_known_url: str = oidc_well_known_url

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
        await self.fetch_well_known_data()
        if self._oidc_well_known_data_last_fetched:
            self.set_up_jwks_client()
        # TODO: throw + log error otherwise
        self._initialized = True

    @property
    def initialized(self) -> bool:
        return self._initialized

    async def validate(self, token: str) -> dict:
        # This relies on access tokens following RFC9068, rather than using the introspection endpoint.

        if not self._initialized:
            raise UninitializedIdPManagerError("Uninitialized IdpManager")
        if not self._jwks_client:
            raise UninitializedIdPManagerError("Missing JWKS Manager")

        sk = self._jwks_client.get_signing_key_from_jwt(token)

        # Assume we have the same set of signing algorithms for access tokens as ID tokens
        return jwt.decode(token, sk, algorithms=self._oidc_well_known_data["id_token_signing_alg_values_supported"])


idp_manager = IdPManager(config.openid_well_known_url)
