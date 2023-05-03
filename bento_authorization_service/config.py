from fastapi import Depends
from functools import lru_cache
from pydantic import BaseSettings
from typing import Annotated, Literal

from .constants import SERVICE_GROUP, SERVICE_ARTIFACT

__all__ = [
    "Config",
    "get_config",
    "ConfigDependency",
]


class Config(BaseSettings):
    service_id: str = f"{SERVICE_GROUP}:{SERVICE_ARTIFACT}"
    service_name: str = "Bento Authorization Service"
    service_url_base_path: str = "http://127.0.0.1:5000"  # Base path to construct URIs from

    # /service-info customization
    service_contact_url: str = "mailto:info@c3g.ca"

    database_uri: str = "postgres://localhost:5432"

    # OpenID well-known URL of the instance Identity Provider to extract endpoints from
    #  - Schemas in this service are written ready for multi-IdP/federation support; however, for now, only
    #    the instance-local IdP is supported.
    openid_well_known_url: str = "https://bentov2auth.local/realms/bentov2/.well-known/openid-configuration"

    permitted_token_algorithms: frozenset = frozenset(
        ["RS256", "RSA-OAEP", "AES"]
    )  # strong keycloak defaults (purposefully exluding HS256)
    # TODO?: ES256/ES384/ES512  ref: https://github.com/keycloak/keycloak/issues/11036

    log_level: Literal["debug", "info", "warning", "error"] = "debug"

    class Config:
        # Make parent Config instances hashable + immutable
        allow_mutation = False
        frozen = True


@lru_cache()
def get_config() -> Config:
    return Config()


ConfigDependency = Annotated[Config, Depends(get_config)]
