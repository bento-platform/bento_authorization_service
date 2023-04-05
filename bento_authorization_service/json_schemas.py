import jsonschema

from .config import config


def _make_schema_id(name: str) -> str:
    return f"{config.service_url_base_path.rstrip('/')}/schemas/{name}.json"


SUBJECT_ISSUER_AND_CLIENT_ID = {
    "$id": _make_schema_id("subject_iss_client"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SubjectIssuerAndClientID",
    "type": "object",
    "properties": {
        "iss": {"type": "string"},  # Issuer
        "client": {"type": "string"},  # Client ID - for service accounts, i.e., API tokens where sub not present
    },
    "required": ["iss", "client"],
}


SUBJECT_ISSUER_AND_SUBJECT_ID = {
    "$id": _make_schema_id("subject_iss_sub"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SubjectIssuerAndSubjectID",
    "type": "object",
    "properties": {
        "iss": {"type": "string"},  # Issuer
        "sub": {"type": "string"},  # Subject
    },
    "required": ["iss", "sub"],
}


SUBJECT_SCHEMA = {
    "$id": _make_schema_id("subject"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Subject",
    "type": "object",
    "oneOf": [
        {
            "properties": {
                "everyone": {"const": True},  # Everyone
            },
            "required": ["everyone"],
        },
        {
            "properties": {
                "group": {"type": "number"},  # Group ID
            },
            "required": ["group"],
        },
        SUBJECT_ISSUER_AND_CLIENT_ID,
        SUBJECT_ISSUER_AND_SUBJECT_ID
    ],
    "additionalProperties": False,
}
SUBJECT_SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(SUBJECT_SCHEMA)


RESOURCE_SCHEMA = {
    "$id": _make_schema_id("resource"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Resource",
    "type": "object",
    "oneOf": [
        {
            "properties": {
                "everything": {"const": True},  # Everything
            },
            "required": ["everything"],
        },
        {
            "properties": {
                "project": {"type": "string", "format": "uuid"},  # Project ID
                "data_type": {"type": "string"},  # Specific data type; if left out, all data types are in-scope
            },
            "required": ["project"],
        },
        {
            "properties": {
                "dataset": {"type": "string", "format": "uuid"},  # Dataset ID
                "data_type": {"type": "string"},  # Specific data type; if left out, all data types are in-scope
            },
            "required": ["dataset"],
        },
    ],
    "additionalProperties": False,
}
RESOURCE_SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(RESOURCE_SCHEMA)


GROUP_MEMBERSHIP_SCHEMA = {
    "$id": _make_schema_id("group_membership"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "GroupMembership",
    "type": "object",
    "oneOf": [
        {
            "properties": {
                "members": {
                    "type": "array",
                    "items": {
                        "oneOf": [SUBJECT_ISSUER_AND_CLIENT_ID, SUBJECT_ISSUER_AND_SUBJECT_ID]
                    },
                },
            },
            "required": ["members"],
        },
        {
            "properties": {
                "expr": {
                    "type": "array",  # bento_lib search-formatted query expression for group membership
                },
            },
            "required": ["expr"],
        },
    ],
    "additionalProperties": False,
}
GROUP_MEMBERSHIP_SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(GROUP_MEMBERSHIP_SCHEMA)


GROUP_SCHEMA = {
    "$id": _make_schema_id("group"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Group",
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "membership": GROUP_MEMBERSHIP_SCHEMA,
    },
    "required": ["membership"],
    "additionalProperties": False,
}
GROUP_SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(GROUP_SCHEMA)
