from bento_lib.search.queries import Query
from typing import Literal, NotRequired, TypedDict

from .policy_engine.permissions import Permission

__all__ = [
    "SubjectEveryone",
    "SubjectGroup",
    "SubjectClient",
    "SubjectUser",
    "Subject",

    "ResourceEverything",
    "ResourceProject",
    "ResourceDataset",
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


class ResourceProject(TypedDict):
    project: str
    data_type: NotRequired[str]


class ResourceDataset(TypedDict):
    dataset: str
    data_type: NotRequired[str]


Resource = ResourceEverything | ResourceProject | ResourceDataset


class Grant(TypedDict):
    id: NotRequired[int]
    subject: Subject
    resource: Resource
    negated: bool
    permission: Permission
    extra: dict


class GroupMembershipList(TypedDict):
    members: list[SubjectClient | SubjectUser]


class GroupMembershipExpression(TypedDict):
    expr: Query


GroupMembership = GroupMembershipList | GroupMembershipExpression


class Group(TypedDict):
    id: NotRequired[int]
    membership: GroupMembership
