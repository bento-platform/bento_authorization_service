import jsonschema
from bento_lib.search import queries as q

from .config import config

__all__ = [
    "TOKEN_DATA",
    "SUBJECT_ISSUER_AND_CLIENT_ID",
    "SUBJECT_ISSUER_AND_SUBJECT_ID",
    "SUBJECT_SCHEMA",
    "SUBJECT_SCHEMA_VALIDATOR",
    "RESOURCE_SCHEMA",
    "RESOURCE_SCHEMA_VALIDATOR",
    "GROUP_MEMBERSHIP_SCHEMA",
    "GROUP_SCHEMA",
]


def _make_schema_id(name: str) -> str:
    return f"{config.service_url_base_path.rstrip('/')}/schemas/{name}.json"


TOKEN_DATA = {
    "$id": _make_schema_id("token_data"),
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "TokenData",
    "type": "object",
    "properties": {
        # Issuer
        "iss": {
            "type": "string",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # Subject
        "sub": {
            "type": "string",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # Client ID (ish)
        "azp": {
            "type": "string",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # Expiry time
        "exp": {
            "type": "integer",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # Issued-at time
        "iat": {
            "type": "integer",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # == "Bearer"
        "typ": {
            "type": "string",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            },
        },
        # Token scope(s) (space-separated list-in-string):
        "scope": {
            "type": "string",
            "search": {
                "operations": [q.SEARCH_OP_EQ, q.SEARCH_OP_IN],
                "queryable": "internal",
            }
        },
    },
    "required": ["iss", "exp", "iat"],
}


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
            "additionalProperties": False,
        },
        {
            "properties": {
                "project": {"type": "string", "format": "uuid"},  # Project ID
                "dataset": {"type": "string", "format": "uuid"},  # Dataset ID (optional)
                "data_type": {"type": "string"},  # Specific data type; if left out, all data types are in-scope
            },
            "required": ["project"],
            "additionalProperties": False,
        },
    ],
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
            "additionalProperties": False,
        },
        {
            "properties": {
                "expr": {
                    "type": "array",  # bento_lib search-formatted query expression for group membership
                },
            },
            "required": ["expr"],
            "additionalProperties": False,
        },
    ],
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
