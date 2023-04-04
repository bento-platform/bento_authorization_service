import jsonschema


SUBJECT_SCHEMA = {
    "$id": "TODO",
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
        {
            "properties": {
                "iss": {"type": "string"},  # Issuer
                "client": {"type": "string"},  # Client ID - for service accounts, i.e., API tokens
            },
            "required": ["iss", "client"],
        },
        {
            "properties": {
                "iss": {"type": "string"},  # Issuer
                "sub": {"type": "string"},  # Subject
            },
            "required": ["iss", "sub"],
        },
    ],
    "additionalProperties": False,
}
SUBJECT_SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(SUBJECT_SCHEMA)


RESOURCE_SCHEMA = {
    "$id": "TODO",
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
