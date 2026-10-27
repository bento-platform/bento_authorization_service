from functools import cache
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import ConfigDependency
from .data_source import JsonDataSource

__all__ = [
    "OptionalBearerToken",
]

security = HTTPBearer(auto_error=False)
OptionalBearerToken = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]


@cache
def get_json_data_source(config: ConfigDependency) -> JsonDataSource:
    return JsonDataSource(None, None)  # TODO


JsonDataSourceDependency = Annotated[Depends(get_json_data_source), JsonDataSource]
