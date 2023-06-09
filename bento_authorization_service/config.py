from fastapi import Depends
from functools import lru_cache
from pydantic import BaseSettings
from typing import Annotated, Any, Literal

from .constants import SERVICE_GROUP, SERVICE_ARTIFACT

__all__ = [
    "Config",
    "get_config",
    "ConfigDependency",
]


class Config(BaseSettings):
    bento_debug: bool = False

    service_id: str = f"{SERVICE_GROUP}:{SERVICE_ARTIFACT}"
    service_name: str = "Bento Authorization Service"
    service_url_base_path: str = "http://127.0.0.1:5000"  # Base path to construct URIs from

    # /service-info customization
    service_contact_url: str = "mailto:info@c3g.ca"

    database_uri: str = "postgres://localhost:5432"

    # OpenID well-known URL of the instance Identity Provider to extract endpoints from
    #  - Schemas in this service are written ready for multi-IdP/federation support; however, for now, only
    #    the instance-local IdP is supported.
    openid_config_url: str = "https://bentov2auth.local/realms/bentov2/.well-known/openid-configuration"

    #  - Default access token audience from Keycloak
    token_audience: str = "account"
    #  - Default set of disabled 'insecure' algorithms (in this case symmetric key algorithms)
    disabled_token_signing_algorithms: frozenset = frozenset(["HS256", "HS384", "HS512"])

    cors_origins: tuple[str, ...]

    log_level: Literal["debug", "info", "warning", "error"] = "debug"

    class Config:
        # Make parent Config instances hashable + immutable
        allow_mutation = False
        frozen = True

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            if field_name == "cors_origins":
                return tuple(x.strip() for x in raw_val.split(";"))
            # noinspection PyUnresolvedReferences
            return cls.json_loads(raw_val)


@lru_cache()
def get_config() -> Config:
    return Config()


ConfigDependency = Annotated[Config, Depends(get_config)]
