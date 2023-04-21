from fastapi import FastAPI

from bento_authorization_service import __version__

from .config import ConfigDependency
from .constants import BENTO_SERVICE_KIND, SERVICE_TYPE
from .db import db
from .idp_manager import get_idp_manager
from .routers.grants import grants_router
from .routers.groups import groups_router
from .routers.policy import policy_router
from .routers.schemas import schema_router


app = FastAPI()

app.include_router(grants_router)
app.include_router(groups_router)
app.include_router(policy_router)
app.include_router(schema_router)


@app.on_event("startup")
async def startup():
    await db.initialize()  # Initialize the database connection pool
    await get_idp_manager().initialize()  # Initialize the IdP manager / token validator


@app.on_event("shutdown")
async def shutdown():
    await db.close()  # Attempt to close all open database connections


@app.get("/service-info")
async def service_info(config: ConfigDependency):
    return {
        "id": config.service_id,
        "name": config.service_name,  # TODO: Should be globally unique?
        "type": SERVICE_TYPE,
        "description": "Authorization & permissions service for the Bento platform.",
        "organization": {
            "name": "C3G",
            "url": "https://www.computationalgenomics.ca"
        },
        "contactUrl": config.service_contact_url,
        "version": __version__,
        "environment": "prod",
        "bento": {
            "serviceKind": BENTO_SERVICE_KIND,
            "dataService": False,
            "gitRepository": "https://github.com/bento-platform/bento_authorization_service",
        },
    }  # TODO: Git info
