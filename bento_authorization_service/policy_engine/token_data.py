from typing import TypedDict

__all__ = ["TokenData"]


class TokenData(TypedDict, total=False):
    iss: str
    sub: str
    aud: str
    azp: str  # Will contain client ID
    typ: str

    iat: int
    exp: int
