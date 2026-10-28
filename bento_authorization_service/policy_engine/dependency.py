from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..config import ConfigDependency
from ..data_provider.provider import AuthzDataProviderDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine
from .pcgl import PcglPolicyEngine


@lru_cache
def get_policy_engine(
    config: ConfigDependency, idp_manager: IdPManagerDependency, provider: AuthzDataProviderDependency
) -> PolicyEngine:
    if config.policy_engine == "pcgl":
        return PcglPolicyEngine(config.pcgl_authz_service_url)
    return BentoPolicyEngine(idp_manager, provider)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
