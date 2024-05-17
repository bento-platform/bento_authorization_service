from bento_authorization_service import __version__
from bento_lib.service_info.constants import SERVICE_GROUP_BENTO
from bento_lib.service_info.helpers import build_bento_service_type

__all__ = [
    "BENTO_SERVICE_KIND",
    "SERVICE_GROUP",
    "SERVICE_ARTIFACT",
    "SERVICE_TYPE",
]

BENTO_SERVICE_KIND = "authorization"

SERVICE_GROUP = SERVICE_GROUP_BENTO
SERVICE_ARTIFACT = BENTO_SERVICE_KIND

SERVICE_TYPE = build_bento_service_type(SERVICE_ARTIFACT, __version__)
