from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated

__all__ = [
    "OptionalBearerToken",
]

security = HTTPBearer()
OptionalBearerToken = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]
