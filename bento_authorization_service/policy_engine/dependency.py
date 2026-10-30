from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..data_provider.provider import AuthzDataProviderDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine

__all__ = ["get_policy_engine", "PolicyEngineDependency"]


@lru_cache
def get_policy_engine(provider: AuthzDataProviderDependency, idp_manager: IdPManagerDependency) -> PolicyEngine:
    return BentoPolicyEngine(idp_manager, provider)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
