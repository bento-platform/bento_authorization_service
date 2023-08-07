from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, RootModel, field_serializer
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
    # Immutable hashable record
    model_config = ConfigDict(frozen=True)


class BaseImmutableRootModel(RootModel):
    # Immutable hashable record
    model_config = ConfigDict(frozen=True)


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


class SubjectModel(BaseImmutableRootModel):
    root: SubjectEveryoneModel | SubjectGroupModel | IssuerAndClientModel | IssuerAndSubjectModel


SUBJECT_EVERYONE = SubjectModel.model_validate(SubjectEveryoneModel(everyone=True))


class GroupMembershipExpr(BaseImmutableModel):
    expr: list  # JSON representation of query format


class GroupMembershipItemModel(BaseImmutableRootModel):
    root: IssuerAndClientModel | IssuerAndSubjectModel


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


class ResourceModel(BaseImmutableRootModel):
    root: ResourceEverythingModel | ResourceSpecificModel


RESOURCE_EVERYTHING = ResourceModel.model_validate(ResourceEverythingModel(everything=True))


class GrantModel(BaseImmutableModel):
    subject: SubjectModel
    resource: ResourceModel
    expiry: datetime | None
    notes: str = ""

    permissions: frozenset[str] = Field(..., min_length=1)

    @field_serializer("permissions")
    def serialize_permissions(self, permissions: frozenset[str], _info):
        # make set serialization have a consistent order
        return sorted(permissions)


class StoredGrantModel(GrantModel):
    id: int
    created: datetime
