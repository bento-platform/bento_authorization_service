import asyncio
import jwt

from bento_lib.auth.permissions import P_VIEW_PERMISSIONS
from fastapi import HTTPException, Request, status
from pydantic import BaseModel
from structlog.stdlib import BoundLogger
from typing import Awaitable, Callable

from bento_authorization_service.authz import authz_middleware
from bento_authorization_service.db import Database
from bento_authorization_service.dependencies import OptionalBearerToken
from bento_authorization_service.idp_manager import BaseIdPManager
from bento_authorization_service.models import ResourceModel
from bento_authorization_service.policy_engine.evaluation import TokenData

__all__ = [
    "check_non_bearer_token_data_use",
    "use_token_data_or_return_error_state",
]


async def check_non_bearer_token_data_use(
    token_data: TokenData | None,
    resources: tuple[ResourceModel, ...],
    request: Request,
    authorization: OptionalBearerToken,
    db: Database,
    idp_manager: BaseIdPManager,
) -> None:
    if token_data is None:
        # Using our own token, so this becomes a public endpoint.
        authz_middleware.mark_authz_done(request)
        return

    async def req_inner(r: ResourceModel):
        await authz_middleware.require_permission_and_flag(
            r, P_VIEW_PERMISSIONS, request, authorization, db, idp_manager
        )

    await asyncio.gather(*map(req_inner, resources))


async def use_token_data_or_return_error_state[T: BaseModel](
    authorization: OptionalBearerToken,
    idp_manager: BaseIdPManager,
    logger: BoundLogger,
    err_state: T,
    create_response: Callable[[TokenData | None], Awaitable[T]],
) -> T:
    try:
        token_data = (await idp_manager.decode(authorization.credentials)) if authorization is not None else None
    except jwt.InvalidAudienceError as e:
        await logger.awarning("got token with bad audience", exception_repr=repr(e))
        return err_state
    except jwt.ExpiredSignatureError:
        logger.warning("got expired token")
        return err_state
    except jwt.DecodeError:
        # Actually throw an HTTP error for this one
        raise HTTPException(detail="Bearer token must be a valid JWT", status_code=status.HTTP_400_BAD_REQUEST)

    return await create_response(token_data)
