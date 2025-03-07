import jwt

from bento_lib.auth.middleware.fastapi import FastApiAuthMiddleware
from bento_lib.auth.permissions import Permission
from fastapi import Depends, HTTPException, Request, status

from .config import get_config
from .db import Database, DatabaseDependency
from .dependencies import OptionalBearerToken
from .idp_manager import IdPManagerDependency, BaseIdPManager
from .logger import get_logger
from .models import ResourceModel
from .policy_engine.evaluation import evaluate
from .utils import extract_token


# TODO: Find a way to DI this
config_for_setup = get_config()
logger_for_setup = get_logger(config_for_setup)


class LocalFastApiAuthMiddleware(FastApiAuthMiddleware):
    def forbidden(self, request: Request) -> HTTPException:
        self.mark_authz_done(request)
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    # Set up our own methods for doing authorization instead of using the middleware default ones, since they make HTTP
    # calls to this service, which we should skip and replace with evaluate() calls.

    async def raise_if_no_resource_access(
        self,
        request: Request,
        token: str,
        resource: ResourceModel,
        required_permission: Permission,
        db: Database,
        idp_manager: BaseIdPManager,
    ) -> None:
        try:
            eval_res = (
                await evaluate(idp_manager, db, self._logger, token, (resource,), (required_permission,))
            )[0][0]
            if not eval_res:
                # Forbidden from accessing or deleting this grant
                raise self.forbidden(request)
        except HTTPException as e:
            raise e  # Pass it on
        except jwt.ExpiredSignatureError:  # Straightforward, expired token - don't bother logging
            raise self.forbidden(request)
        except Exception as e:  # Could not properly run evaluate(); return forbidden!
            await self._logger.aexception(
                f"encountered error while checking permissions for request {request.method} {request.url.path}: ",
                exc_info=e,
                request={"method": request.method, "path": request.url.path},
            )
            raise self.forbidden(request)

    async def require_permission_and_flag(
        self,
        resource: ResourceModel,
        permission: Permission,
        request: Request,
        authorization: OptionalBearerToken,
        db: Database,
        idp_manager: BaseIdPManager,
    ):
        await self.raise_if_no_resource_access(
            request,
            extract_token(authorization),
            resource,
            permission,
            db,
            idp_manager,
        )
        # Flag that we have thought about auth
        authz_middleware.mark_authz_done(request)

    def require_permission_dependency(self, resource: ResourceModel, permission: Permission):
        async def _inner(
            request: Request,
            authorization: OptionalBearerToken,
            db: DatabaseDependency,
            idp_manager: IdPManagerDependency,
        ):
            return await self.require_permission_and_flag(
                resource,
                permission,
                request,
                authorization,
                db,
                idp_manager,
            )

        return Depends(_inner)


authz_middleware = LocalFastApiAuthMiddleware.build_from_fastapi_pydantic_config(config_for_setup, logger_for_setup)
