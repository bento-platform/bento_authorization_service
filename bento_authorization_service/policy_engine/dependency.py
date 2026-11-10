from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..config import ConfigDependency
from ..data_provider.provider import AuthzDataProviderDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine
from .pcgl import PcglPolicyEngine

__all__ = ["get_policy_engine", "PolicyEngineDependency"]


@lru_cache
def get_policy_engine(
    config: ConfigDependency, idp_manager: IdPManagerDependency, provider: AuthzDataProviderDependency
) -> PolicyEngine:
    if config.policy_engine == "pcgl":
        return PcglPolicyEngine(
            idp_manager,
            provider,
            jwt_access_tokens=config.jwt_access_tokens,
            pcgl_authz_url=config.pcgl_authz_service_url,
            pcgl_service_id=config.pcgl_service_id,
            pcgl_service_secret=config.pcgl_service_secret,
            pcgl_service_token_lifespan=config.pcgl_service_token_lifespan,
            pcgl_action_endpoint=config.pcgl_authz_action_endpoint,
            pcgl_action_method=config.pcgl_authz_action_method,
            pcgl_request_timeout=config.pcgl_request_timeout,
            verify_ssl=not config.bento_debug,
        )
    return BentoPolicyEngine(idp_manager, provider, jwt_access_tokens=config.jwt_access_tokens)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
