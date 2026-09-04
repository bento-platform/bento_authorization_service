from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..config import ConfigDependency
from ..db import DatabaseDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine
from .pcgl import PcglPolicyEngine

__all__ = ["get_policy_engine", "PolicyEngineDependency"]


@lru_cache
def get_policy_engine(
    config: ConfigDependency, db: DatabaseDependency, idp_manager: IdPManagerDependency
) -> PolicyEngine:
    if config.policy_engine == "pcgl":
        return PcglPolicyEngine(config.pcgl_authz_service_url)
    return BentoPolicyEngine(db, idp_manager)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
