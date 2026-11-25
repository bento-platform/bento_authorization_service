from typing import TypedDict

__all__ = ["TokenData"]


class TokenData(TypedDict, total=False):
    iss: str
    sub: str
    aud: str | list[str]
    azp: str  # Client ID (OIDC)
    client_id: str  # Client ID (RFC 9068 JWT access tokens)
    typ: str

    iat: int
    exp: int
