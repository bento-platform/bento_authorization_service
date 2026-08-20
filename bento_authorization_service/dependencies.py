from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

__all__ = [
    "OptionalBearerToken",
]

security = HTTPBearer(auto_error=False)
OptionalBearerToken = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]
