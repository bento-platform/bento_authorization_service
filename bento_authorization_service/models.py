from pydantic import BaseModel
from typing import Literal, Optional

__all__ = [
    "SubjectModel",
    "ResourceModel",
    "GroupMembershipItemModel",
    "GroupModel",
    "GrantModel",
]


class BaseImmutableModel(BaseModel):
    class Config:
        frozen = True    # Immutable hashable record


class IssuerAndClientModel(BaseImmutableModel):
    iss: str
    client: str


class IssuerAndSubjectModel(BaseImmutableModel):
    iss: str
    sub: str


class SubjectEveryoneModel(BaseImmutableModel):
    everyone: Literal[True]


class SubjectGroupModel(BaseImmutableModel):
    group: int


class SubjectModel(BaseImmutableModel):
    __root__: SubjectEveryoneModel | SubjectGroupModel | IssuerAndClientModel | IssuerAndSubjectModel


class GroupMembershipExpr(BaseImmutableModel):
    expr: list  # JSON representation of query format


class GroupMembershipItemModel(BaseImmutableModel):
    __root__: IssuerAndClientModel | IssuerAndSubjectModel


class GroupMembershipMembers(BaseImmutableModel):
    members: list[GroupMembershipItemModel]


class GroupModel(BaseImmutableModel):
    membership: GroupMembershipExpr | GroupMembershipMembers


class ResourceEverythingModel(BaseImmutableModel):
    everything: Literal[True]


class ResourceSpecificModel(BaseImmutableModel):
    project: str
    dataset: Optional[str] = None
    data_type: Optional[str] = None


class ResourceModel(BaseImmutableModel):
    __root__: ResourceEverythingModel | ResourceSpecificModel


class GrantModel(BaseImmutableModel):
    subject: SubjectModel
    resource: ResourceModel
    permission: str
    extra: dict
