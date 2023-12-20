from bento_lib.config.pydantic import BentoBaseConfig
from fastapi import Depends
from functools import lru_cache
from typing import Annotated

from .constants import SERVICE_GROUP, SERVICE_ARTIFACT

__all__ = [
    "Config",
    "get_config",
    "ConfigDependency",
]


class Config(BentoBaseConfig):
    # the superclass has this as a required field - we ignore it since this IS the authz service
    # TODO: should this maybe be a [str | None] in bento_lib?
    bento_authz_service_url: str = ""

    service_id: str = f"{SERVICE_GROUP}:{SERVICE_ARTIFACT}"
    service_name: str = "Bento Authorization Service"
    service_url_base_path: str = "http://127.0.0.1:5000"  # Base path to construct URIs from

    database_uri: str = "postgres://localhost:5432"

    # OpenID well-known URL of the instance Identity Provider to extract endpoints from
    #  - Schemas in this service are written ready for multi-IdP/federation support; however, for now, only
    #    the instance-local IdP is supported.
    openid_config_url: str = "https://bentov2auth.local/realms/bentov2/.well-known/openid-configuration"

    #  - Default access token audience from Keycloak
    token_audience: str = "account"
    #  - Default set of disabled 'insecure' algorithms (in this case symmetric key algorithms)
    disabled_token_signing_algorithms: frozenset = frozenset(["HS256", "HS384", "HS512"])


@lru_cache()
def get_config() -> Config:
    return Config()


ConfigDependency = Annotated[Config, Depends(get_config)]
