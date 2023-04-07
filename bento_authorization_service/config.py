from pydantic import BaseSettings

from .constants import SERVICE_GROUP, SERVICE_ARTIFACT

__all__ = [
    "Config",
    "config",
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


config = Config()
