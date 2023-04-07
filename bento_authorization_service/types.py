from bento_lib.search.queries import Query
from typing import Literal, TypedDict

from .policy_engine.permissions import Permission

__all__ = [
    "SubjectEveryone",
    "SubjectGroup",
    "SubjectClient",
    "SubjectUser",
    "Subject",

    "ResourceEverything",
    "ResourceProjectOrDatasetOrDataType",
    "Resource",

    "Grant",

    "GroupMembership",
    "Group",
]


class SubjectEveryone(TypedDict):
    everyone: Literal[True]


class SubjectGroup(TypedDict):
    group: int


class SubjectClient(TypedDict):
    iss: str
    client: str


class SubjectUser(TypedDict):
    iss: str
    sub: str


Subject = SubjectEveryone | SubjectGroup | SubjectClient | SubjectUser


class ResourceEverything(TypedDict):
    everything: Literal[True]


class _ResourceProjectBase(TypedDict):
    project: str


class ResourceProjectOrDatasetOrDataType(_ResourceProjectBase, total=False):
    dataset: str
    data_type: str


Resource = ResourceEverything | ResourceProjectOrDatasetOrDataType


class _GrantBase(TypedDict):
    subject: Subject
    resource: Resource
    negated: bool
    permission: Permission
    extra: dict


class Grant(_GrantBase, total=False):
    id: int


class GroupMembershipList(TypedDict):
    members: list[SubjectClient | SubjectUser]


class GroupMembershipExpression(TypedDict):
    expr: Query


GroupMembership = GroupMembershipList | GroupMembershipExpression


class _GroupBase(TypedDict):
    membership: GroupMembership


class Group(_GroupBase, total=False):
    id: int
