import json

from fastapi import Depends
from functools import lru_cache
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, EnvSettingsSource, PydanticBaseSettingsSource, SettingsConfigDict
from typing import Annotated, Any, Literal

from .constants import SERVICE_GROUP, SERVICE_ARTIFACT

__all__ = [
    "Config",
    "get_config",
    "ConfigDependency",
]


class CorsOriginsParsingSource(EnvSettingsSource):
    def prepare_field_value(self, field_name: str, field: FieldInfo, value: Any, value_is_complex: bool) -> Any:
        if field_name == "cors_origins":
            return tuple(x.strip() for x in value.split(";")) if value is not None else ()
        return json.loads(value) if value_is_complex else value


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

    # Make Config instances hashable + immutable
    model_config = SettingsConfigDict(frozen=True)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (CorsOriginsParsingSource(settings_cls),)


@lru_cache()
def get_config() -> Config:
    return Config()


ConfigDependency = Annotated[Config, Depends(get_config)]
