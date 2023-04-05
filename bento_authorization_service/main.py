from fastapi import FastAPI

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
    return {}  # TODO
