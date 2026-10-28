from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from ..data_source import BaseDataSource
from ..db import DatabaseDependency
from ..dependencies import JsonDataSourceDependency
from ..idp_manager import IdPManagerDependency
from .base import PolicyEngine
from .evaluation import BentoPolicyEngine

__all__ = ["get_policy_engine", "PolicyEngineDependency"]


@lru_cache
def get_policy_engine(
    db: DatabaseDependency, json_ds: JsonDataSourceDependency, idp_manager: IdPManagerDependency
) -> PolicyEngine:
    sources: list[BaseDataSource] = [db]
    if json_ds:
        sources.append(json_ds)
    return BentoPolicyEngine(tuple(sources), idp_manager)


PolicyEngineDependency = Annotated[PolicyEngine, Depends(get_policy_engine)]
