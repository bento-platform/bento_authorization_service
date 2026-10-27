from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..data_source import JsonDataSource
from ..db import DatabaseDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine

__all__ = ["get_policy_engine", "PolicyEngineDependency"]


@lru_cache
def get_policy_engine(
    db: DatabaseDependency, json_ds: JsonDataSource, idp_manager: IdPManagerDependency
) -> PolicyEngine:
    return BentoPolicyEngine((db, json_ds), idp_manager)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
