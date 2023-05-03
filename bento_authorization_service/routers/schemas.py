from fastapi import APIRouter

from bento_authorization_service import json_schemas as js

__all__ = ["schema_router"]

schema_router = APIRouter(prefix="/schemas")


@schema_router.get("/token_data.json")
def token_data_json_schema():
    # Public endpoint, no permissions checks required
    return js.TOKEN_DATA
