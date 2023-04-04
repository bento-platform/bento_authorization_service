from fastapi import FastAPI

from .db import db


app = FastAPI()


@app.on_event("startup")
async def startup():
    await db.initialize()  # Initialize the database connection pool


@app.on_event("shutdown")
async def shutdown():
    await db.close()  # Attempt to close all open database connections


@app.get("/service-info")
async def service_info():
    return {}  # TODO
