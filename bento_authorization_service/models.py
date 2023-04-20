from pydantic import BaseModel
from typing import Literal, Optional

__all__ = [
    "SubjectModel",
    "ResourceModel",
    "GroupMembershipItemModel",
    "GroupModel",
    "GrantModel",
]


class SubjectModel(BaseModel):
    # janky way of representing the true Union type for Subject
    # TODO: try create_model_from_typeddict in pydantic 2

    everyone: Optional[Literal[True]] = None
    group: Optional[int] = None
    iss: Optional[str] = None
    client: Optional[str] = None
    sub: Optional[str] = None


class GroupMembershipItemModel(BaseModel):
    expr: Optional[str] = None
    iss: Optional[str] = None
    client: Optional[str] = None
    sub: Optional[str] = None


class GroupModel(BaseModel):
    members: list[GroupMembershipItemModel]


class ResourceModel(BaseModel):
    # janky way of representing the true Union type for Resource
    # TODO: try create_model_from_typeddict in pydantic 2

    everything: Optional[Literal[True]] = None
    project: Optional[str] = None
    dataset: Optional[str] = None
    data_type: Optional[str] = None


class GrantModel(BaseModel):
    # janky way of representing the true Union type for Grant
    # TODO: try create_model_from_typeddict in pydantic 2

    subject: SubjectModel
    resource: ResourceModel
    permission: str
    extra: dict
