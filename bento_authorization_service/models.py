from datetime import datetime
from pydantic import BaseModel, Field
from typing import Literal

__all__ = [
    # Subject:
    "SubjectEveryoneModel",
    "SubjectGroupModel",
    "BaseIssuerModel",
    "IssuerAndClientModel",
    "IssuerAndSubjectModel",
    "SubjectModel",
    "SUBJECT_EVERYONE",
    # Resource:
    "ResourceEverythingModel",
    "ResourceSpecificModel",
    "ResourceModel",
    "RESOURCE_EVERYTHING",
    # Group:
    "GroupMembershipExpr",
    "GroupMembershipItemModel",
    "GroupMembershipMembers",
    "GroupMembership",
    "GroupModel",
    "StoredGroupModel",
    # Grant:
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


SUBJECT_EVERYONE = SubjectModel(__root__=SubjectEveryoneModel(everyone=True))


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
    notes: str = ""


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


RESOURCE_EVERYTHING = ResourceModel(__root__=ResourceEverythingModel(everything=True))


class GrantModel(BaseImmutableModel):
    subject: SubjectModel
    resource: ResourceModel
    expiry: datetime | None
    notes: str = ""

    permissions: frozenset[str] = Field(..., min_items=1)


class StoredGrantModel(GrantModel):
    id: int
    created: datetime
