from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from bento_authorization_service import __version__

from .config import ConfigDependency
from .constants import BENTO_SERVICE_KIND, SERVICE_TYPE
from .routers.grants import grants_router
from .routers.groups import groups_router
from .routers.policy import policy_router
from .routers.schemas import schema_router
from .routers.utils import public_endpoint_dependency


app = FastAPI()

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

    # Set flag saying the request hasn't had its permissions determined yet.
    request.state.determined_authz = False

    # Run the next steps in the response chain
    response: Response = await call_next(request)

    if not request.state.determined_authz:
        # Next in response chain didn't properly think about auth; return 403
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Forbidden"})

    # Otherwise, return the response as normal
    return response


@app.get("/service-info", dependencies=[public_endpoint_dependency])
async def service_info(config: ConfigDependency):
    # Public endpoint, no permissions checks required
    return {
        "id": config.service_id,
        "name": config.service_name,  # TODO: Should be globally unique?
        "type": SERVICE_TYPE,
        "description": "Authorization & permissions service for the Bento platform.",
        "organization": {"name": "C3G", "url": "https://www.computationalgenomics.ca"},
        "contactUrl": config.service_contact_url,
        "version": __version__,
        "environment": "prod",
        "bento": {
            "serviceKind": BENTO_SERVICE_KIND,
            "dataService": False,
            "gitRepository": "https://github.com/bento-platform/bento_authorization_service",
        },
    }  # TODO: Git info
