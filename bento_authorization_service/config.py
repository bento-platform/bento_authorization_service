from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from bento_lib.config.pydantic import BentoFastAPIBaseConfig
from fastapi import Depends
from pydantic import BeforeValidator, SecretStr, model_validator
from pydantic_settings import SettingsConfigDict

from .constants import SERVICE_ARTIFACT, SERVICE_GROUP

__all__ = [
    "Config",
    "get_config",
    "ConfigDependency",
]


def ensure_blank_to_none(value: Any) -> Any:
    if not value:
        return None
    return value


class Config(BentoFastAPIBaseConfig):
    # Don't echo raw settings (secrets, database URI) in validation errors at startup
    model_config = SettingsConfigDict(hide_input_in_errors=True)

    # the superclass has this as a required field - we ignore it since this IS the authz service
    # TODO: should this maybe be a [str | None] in bento_lib?
    bento_authz_service_url: str = ""

    service_id: str = f"{SERVICE_GROUP}:{SERVICE_ARTIFACT}"
    service_name: str = "Bento Authorization Service"

    policy_engine: Literal["bento", "pcgl"] = "bento"

    database_uri: str = "postgres://localhost:5432"

    static_authz_data_path: Annotated[Path | None, BeforeValidator(ensure_blank_to_none)] = None

    # OpenID well-known URL of the instance Identity Provider to extract endpoints from
    #  - Schemas in this service are written ready for multi-IdP/federation support; however, for now, only
    #    the instance-local IdP is supported.
    openid_config_url: str = "https://bentov2auth.local/realms/bentov2/.well-known/openid-configuration"

    #  - Default access token audience from Keycloak
    token_audience: str = "account"
    #  - Default set of disabled 'insecure' algorithms (in this case symmetric key algorithms)
    disabled_token_signing_algorithms: frozenset = frozenset(["HS256", "HS384", "HS512"])
    #  - Whether we expect access tokens to be JWTs. If False, bearer tokens are not decoded, so Bento grants treat
    #    the request as anonymous (the PCGL engine still forwards the raw token to the PCGL authz service).
    jwt_access_tokens: bool = True

    # PCGL authorization service connection (required if policy_engine is "pcgl"; validated below).
    # The PCGL engine only delegates download:metadata on {project, dataset, data_type: experiment} resources.
    #  - Base URL of the PCGL authz service
    pcgl_authz_service_url: str = ""
    #  - PCGL service public ID for calls to the PCGL authz service
    pcgl_service_id: str = ""
    #  - PCGL service secret/UUID for calls to the PCGL authz service
    pcgl_service_secret: SecretStr = SecretStr("")
    #  - PCGL service token lifespan, in seconds
    pcgl_service_token_lifespan: int = 1500  # defaults to 25 minutes
    #  - Action sent to PCGL /allowed; must match the action Bento is registered for in the PCGL authz service.
    pcgl_authz_action_endpoint: str = "/export/study"
    pcgl_authz_action_method: str = "GET"
    #  - Total timeout for each request to the PCGL authz service, in seconds
    pcgl_request_timeout: float = 10

    @model_validator(mode="after")
    def check_pcgl_settings(self) -> Self:
        if self.policy_engine == "pcgl":
            missing = [
                name
                for name, value in (
                    ("pcgl_authz_service_url", self.pcgl_authz_service_url),
                    ("pcgl_service_id", self.pcgl_service_id),
                    ("pcgl_service_secret", self.pcgl_service_secret.get_secret_value()),
                    ("pcgl_authz_action_endpoint", self.pcgl_authz_action_endpoint),
                    ("pcgl_authz_action_method", self.pcgl_authz_action_method),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"policy_engine is 'pcgl' but these settings are empty: {', '.join(missing)}")
            if self.pcgl_service_token_lifespan <= 0:
                raise ValueError("pcgl_service_token_lifespan must be greater than 0")
            if self.pcgl_request_timeout <= 0:
                raise ValueError("pcgl_request_timeout must be greater than 0")
        return self


@lru_cache
def get_config() -> Config:
    return Config()


ConfigDependency = Annotated[Config, Depends(get_config)]
