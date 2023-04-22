from pydantic import BaseModel
from typing import Literal, Optional

__all__ = [
    "SubjectModel",
    "ResourceModel",
    "GroupMembershipItemModel",
    "GroupModel",
    "GrantModel",
]


class IssuerAndClientModel(BaseModel):
    iss: str
    client: str


class IssuerAndSubjectModel(BaseModel):
    iss: str
    sub: str


class SubjectEveryoneModel(BaseModel):
    everyone: Literal[True]


class SubjectGroupModel(BaseModel):
    group: int


class SubjectModel(BaseModel):
    __root__: SubjectEveryoneModel | SubjectGroupModel | IssuerAndClientModel | IssuerAndSubjectModel


class GroupMembershipExpr(BaseModel):
    expr: list  # JSON representation of query format


class GroupMembershipItemModel(BaseModel):
    __root__: IssuerAndClientModel | IssuerAndSubjectModel


class GroupMembershipMembers(BaseModel):
    members: list[GroupMembershipItemModel]


class GroupModel(BaseModel):
    membership: GroupMembershipExpr | GroupMembershipMembers


class ResourceEverythingModel(BaseModel):
    everything: Literal[True]


class ResourceSpecificModel(BaseModel):
    project: str
    dataset: Optional[str] = None
    data_type: Optional[str] = None


class ResourceModel(BaseModel):
    __root__: ResourceEverythingModel | ResourceSpecificModel


class GrantModel(BaseModel):
    subject: SubjectModel
    resource: ResourceModel
    permission: str
    extra: dict
