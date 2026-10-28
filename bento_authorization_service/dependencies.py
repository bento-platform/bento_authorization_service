from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import ConfigDependency
from .data_source import JsonDataSource

__all__ = [
    "JsonDataSourceDependency",
    "OptionalBearerToken",
]

security = HTTPBearer(auto_error=False)
OptionalBearerToken = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]


@lru_cache
def get_json_data_source(config: ConfigDependency) -> JsonDataSource | None:
    # return JsonDataSource(None, None)  # TODO
    return None


JsonDataSourceDependency = Annotated[JsonDataSource | None, Depends(get_json_data_source)]
