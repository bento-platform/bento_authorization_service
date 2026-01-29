from fastapi import APIRouter, Response

from .. import json_schemas as js
from ..authz import authz_middleware

__all__ = ["schema_router"]

schema_router = APIRouter(prefix="/schemas")


@schema_router.get("/token_data.json", dependencies=[authz_middleware.dep_public_endpoint()])
def token_data_json_schema(response: Response):
    # Public endpoint, no permissions checks required
    # unchanging public JSON served; cache for a day:
    response.headers["Cache-Control"] = "public, max-age=86400"
    return js.TOKEN_DATA
