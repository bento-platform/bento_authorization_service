from bento_lib.responses.fastapi_errors import http_exception_handler_factory, validation_exception_handler_factory
from bento_lib.service_info.helpers import build_service_info_from_pydantic_config
from bento_lib.service_info.types import BentoExtraServiceInfo
from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import ConfigDependency, get_config
from .constants import BENTO_SERVICE_KIND, SERVICE_TYPE
from .logger import logger
from .routers.grants import grants_router
from .routers.groups import groups_router
from .routers.policy import policy_router
from .routers.schemas import schema_router
from .routers.utils import MarkAuthzDone, public_endpoint_dependency


# TODO: Find a way to DI this
config_for_setup = get_config()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=config_for_setup.cors_origins,
    allow_headers=["Authorization"],
    allow_credentials=True,
    allow_methods=["*"],
)

app.exception_handler(StarletteHTTPException)(http_exception_handler_factory(logger, MarkAuthzDone))
app.exception_handler(RequestValidationError)(validation_exception_handler_factory(MarkAuthzDone))

app.include_router(grants_router)
app.include_router(groups_router)
app.include_router(policy_router)
app.include_router(schema_router)


@app.middleware("http")
async def permissions_enforcement(request: Request, call_next) -> Response:
    """
    Permissions enforcement middleware. We require all endpoints to explicitly set a flag to say they have 'thought'
    about permissions and decided the request should go through (or be rejected).
    """

    if request.method == "OPTIONS":  # Allow pre-flight responses through
        return await call_next(request)

    # Set flag saying the request hasn't had its permissions determined yet.
    request.state.determined_authz = False

    # Run the next steps in the response chain
    response: Response = await call_next(request)

    if not request.state.determined_authz:
        # Next in response chain didn't properly think about auth; return 403
        logger.warning(
            f"Masking true response with 403 since determined_authz was not set: {request.url} {response.status_code}"
        )
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Forbidden"})

    # Otherwise, return the response as normal
    return response


@app.get("/service-info", dependencies=[public_endpoint_dependency])
async def service_info(config: ConfigDependency):
    bento_info: BentoExtraServiceInfo = {
        "serviceKind": BENTO_SERVICE_KIND,
        "dataService": False,
        "gitRepository": "https://github.com/bento-platform/bento_authorization_service",
    }
    return await build_service_info_from_pydantic_config(config, logger, bento_info, SERVICE_TYPE, __version__)
