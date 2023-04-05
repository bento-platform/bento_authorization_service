from fastapi import FastAPI

from bento_authorization_service import __version__

from .config import config
from .constants import BENTO_SERVICE_KIND, SERVICE_TYPE
from .db import db
from .routers.grants import grants_router
from .routers.groups import groups_router
from .routers.policy import policy_router


app = FastAPI()

app.include_router(grants_router)
app.include_router(groups_router)
app.include_router(policy_router)


@app.on_event("startup")
async def startup():
    await db.initialize()  # Initialize the database connection pool


@app.on_event("shutdown")
async def shutdown():
    await db.close()  # Attempt to close all open database connections


@app.get("/service-info")
async def service_info():
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
