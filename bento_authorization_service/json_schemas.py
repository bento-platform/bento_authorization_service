from bento_lib.search import queries as q

from .config import get_config

__all__ = [
    "TOKEN_DATA",
]


def _make_schema_id(name: str) -> str:
    return f"{get_config().service_url_base_path.rstrip('/')}/schemas/{name}.json"


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
            },
        },
    },
    "required": ["iss", "exp", "iat"],
}
