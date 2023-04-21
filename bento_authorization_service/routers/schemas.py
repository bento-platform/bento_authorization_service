from fastapi import APIRouter

from bento_authorization_service import json_schemas as js

__all__ = ["schema_router"]

schema_router = APIRouter(prefix="/schemas")


@schema_router.get("/subject_iss_client.json")
def subject_iss_client_json_schema():
    return js.SUBJECT_ISSUER_AND_CLIENT_ID


@schema_router.get("/subject_iss_sub.json")
def subject_iss_sub_json_schema():
    return js.SUBJECT_ISSUER_AND_SUBJECT_ID


@schema_router.get("/subject.json")
def subject_json_schema():
    return js.SUBJECT_SCHEMA


@schema_router.get("/resource.json")
def resource_json_schema():
    return js.RESOURCE_SCHEMA


@schema_router.get("/group_membership.json")
def group_membership_json_schema():
    return js.GROUP_MEMBERSHIP_SCHEMA


@schema_router.get("/group.json")
def group_json_schema():
    return js.GROUP_SCHEMA


@schema_router.get("/grant.json")
def grant_json_schema():
    return js.GRANT_SCHEMA
