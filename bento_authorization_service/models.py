from pydantic import create_model_from_typeddict
from .types import Resource, Grant

__all__ = [
    "ResourceModel",
    "GrantModel",
]

ResourceModel = create_model_from_typeddict(Resource)
GrantModel = create_model_from_typeddict(Grant)
