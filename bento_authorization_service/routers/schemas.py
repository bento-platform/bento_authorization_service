from fastapi import APIRouter

from ..json_schemas import SUBJECT_SCHEMA, RESOURCE_SCHEMA

__all__ = ["schema_router"]

schema_router = APIRouter(prefix="/schemas")


@schema_router.get("/subject.json")
def subject_json_schema():
    return SUBJECT_SCHEMA


@schema_router.get("/resource.json")
def resource_json_schema():
    return RESOURCE_SCHEMA
