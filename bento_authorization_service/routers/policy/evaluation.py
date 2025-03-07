from bento_lib.auth.permissions import PERMISSIONS_BY_STRING, Permission
from fastapi import Request
from pydantic import BaseModel
from structlog.stdlib import BoundLogger

from bento_authorization_service.db import Database, DatabaseDependency
from bento_authorization_service.dependencies import OptionalBearerToken
from bento_authorization_service.idp_manager import IdPManager, IdPManagerDependency
from bento_authorization_service.logger import LoggerDependency
from bento_authorization_service.models import ResourceModel
from bento_authorization_service.policy_engine.evaluation import TokenData, evaluate

from .common import check_non_bearer_token_data_use, use_token_data_or_return_error_state
from .router import policy_router


class EvaluationMatrixRequest(BaseModel):
    token_data: TokenData | None = None
    resources: tuple[ResourceModel, ...]
    permissions: tuple[str, ...]


class EvaluationScalarRequest(BaseModel):
    token_data: TokenData | None = None
    resource: ResourceModel
    permission: str


class EvaluationMatrixResponse(BaseModel):
    result: list[list[bool]]


class EvaluationScalarResponse(BaseModel):
    result: bool


async def _inner_req_evaluate(
    request: Request,
    authorization: OptionalBearerToken,
    req_token_data: TokenData | None,
    resources: tuple[ResourceModel, ...],
    permissions: tuple[Permission, ...],
    db: Database,
    idp_manager: IdPManager,
    logger: BoundLogger,
) -> EvaluationMatrixResponse:
    await check_non_bearer_token_data_use(req_token_data, resources, request, authorization, db, idp_manager)

    # Given a token or token-like data, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    async def _create_response(token_data: TokenData | None):
        return EvaluationMatrixResponse(
            result=await evaluate(idp_manager, db, logger, token_data, resources, permissions)
        )

    return await use_token_data_or_return_error_state(
        authorization,
        idp_manager,
        logger,
        err_state=EvaluationMatrixResponse(result=[[False] * len(permissions) for _ in resources]),
        create_response=_create_response,
    )


@policy_router.post("/evaluate")
async def req_evaluate(
    request: Request,
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationMatrixRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    logger: LoggerDependency,
) -> EvaluationMatrixResponse:
    # Semi-public endpoint; no permissions checks required unless we've provided a dictionary of 'token-like' data,
    # in which case we need the view:grants permission, since this is a form of token introspection, essentially.

    # Endpoint permissions: available to everyone if we access it with our own token, since this endpoint's contents
    # are token-specific.

    # A rate limiter should be placed in front of this service, especially this endpoint, since it is public.

    # Request structure:
    #   Header: Authorization?: Bearer <token>
    #   Post body: {resources: {...}, permissions: [...], token_data?: {...}}

    return await _inner_req_evaluate(
        request,
        authorization,
        evaluation_request.token_data,
        evaluation_request.resources,
        tuple(PERMISSIONS_BY_STRING[p] for p in evaluation_request.permissions),
        db,
        idp_manager,
        logger,
    )


@policy_router.post("/evaluate_one")
async def req_evaluate_one(
    request: Request,
    authorization: OptionalBearerToken,
    evaluation_request: EvaluationScalarRequest,
    db: DatabaseDependency,
    idp_manager: IdPManagerDependency,
    logger: LoggerDependency,
) -> EvaluationScalarResponse:
    # Same concept as above, except with just one resource + permission. We make this a separate endpoint to help
    # prevent 'decoding' / false permissions-granting errors, where someone checks the truthiness of, e.g., [[False]],
    # which would give True when it shouldn't.

    return EvaluationScalarResponse(
        result=(
            await _inner_req_evaluate(
                request,
                authorization,
                evaluation_request.token_data,
                (evaluation_request.resource,),
                (PERMISSIONS_BY_STRING[evaluation_request.permission],),
                db,
                idp_manager,
                logger,
            )
        ).result[0][0]
    )
