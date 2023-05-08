from fastapi import APIRouter

from .. import json_schemas as js
from .utils import public_endpoint_dependency

__all__ = ["schema_router"]

schema_router = APIRouter(prefix="/schemas")


@schema_router.get("/token_data.json", dependencies=[public_endpoint_dependency])
def token_data_json_schema():
    # Public endpoint, no permissions checks required
    return js.TOKEN_DATA
