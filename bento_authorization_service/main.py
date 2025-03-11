from bento_lib.apps.fastapi import BentoFastAPI
from bento_lib.service_info.types import BentoExtraServiceInfo

from . import __version__
from .authz import authz_middleware
from .config import get_config
from .constants import BENTO_SERVICE_KIND, SERVICE_TYPE
from .logger import get_logger
from .routers.all_permissions import all_permissions_router
from .routers.grants import grants_router
from .routers.groups import groups_router
from .routers.policy import policy_router
from .routers.schemas import schema_router


BENTO_SERVICE_INFO: BentoExtraServiceInfo = {
    "serviceKind": BENTO_SERVICE_KIND,
    "dataService": False,
    "gitRepository": "https://github.com/bento-platform/bento_authorization_service",
}


# TODO: Find a way to DI this
config_for_setup = get_config()
logger_for_setup = get_logger(config_for_setup)

app = BentoFastAPI(
    authz_middleware,
    config_for_setup,
    logger_for_setup,
    BENTO_SERVICE_INFO,
    SERVICE_TYPE,
    __version__,
    configure_structlog_access_logger=True,
)

app.include_router(all_permissions_router)
app.include_router(grants_router)
app.include_router(groups_router)
app.include_router(policy_router)
app.include_router(schema_router)
