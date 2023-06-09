from bento_authorization_service import __version__

__all__ = [
    "BENTO_SERVICE_KIND",
    "SERVICE_GROUP",
    "SERVICE_ARTIFACT",
    "SERVICE_TYPE",
]

BENTO_SERVICE_KIND = "authorization"

SERVICE_GROUP = "ca.c3g.bento"
SERVICE_ARTIFACT = BENTO_SERVICE_KIND

SERVICE_TYPE = {
    "group": SERVICE_GROUP,
    "artifact": SERVICE_ARTIFACT,
    "version": __version__,
}
