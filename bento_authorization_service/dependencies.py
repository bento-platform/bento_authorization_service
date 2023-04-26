from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated

__all__ = [
    "OptionalBearerToken",
]

security = HTTPBearer(auto_error=False)
OptionalBearerToken = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]
