import json
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

__all__ = [
    "extract_token",
    "json_model_dump_kwargs",
]


def extract_token(authorization: HTTPAuthorizationCredentials | None) -> str | None:
    return authorization.credentials if authorization is not None else None


def json_model_dump_kwargs(x: BaseModel, **kwargs) -> str:
    return json.dumps(x.model_dump(mode="json"), **kwargs)
