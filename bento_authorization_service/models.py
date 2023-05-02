from datetime import datetime
from pydantic import BaseModel
from typing import Literal

__all__ = [
    "SubjectEveryoneModel",
    "SubjectGroupModel",
    "BaseIssuerModel",
    "IssuerAndClientModel",
    "IssuerAndSubjectModel",
    "SubjectModel",

    "ResourceEverythingModel",
    "ResourceSpecificModel",
    "ResourceModel",

    "GroupMembershipExpr",
    "GroupMembershipItemModel",
    "GroupMembershipMembers",
    "GroupMembership",
    "GroupModel",
    "StoredGroupModel",
    "GrantModel",
    "StoredGrantModel",
]


class BaseImmutableModel(BaseModel):
    class Config:
        # Immutable hashable record
        allow_mutation = False
        frozen = True


class BaseIssuerModel(BaseImmutableModel):
    iss: str


class IssuerAndClientModel(BaseIssuerModel):
    client: str


class IssuerAndSubjectModel(BaseIssuerModel):
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


GroupMembership = GroupMembershipExpr | GroupMembershipMembers


class GroupModel(BaseImmutableModel):
    name: str
    membership: GroupMembership
    expiry: datetime | None


class StoredGroupModel(GroupModel):
    id: int
    created: datetime


class ResourceEverythingModel(BaseImmutableModel):
    everything: Literal[True]


class ResourceSpecificModel(BaseImmutableModel):
    project: str
    dataset: str | None = None
    data_type: str | None = None


class ResourceModel(BaseImmutableModel):
    __root__: ResourceEverythingModel | ResourceSpecificModel


class GrantModel(BaseImmutableModel):
    subject: SubjectModel
    resource: ResourceModel
    permission: str
    extra: dict
    expiry: datetime | None


class StoredGrantModel(GrantModel):
    id: int
    created: datetime
