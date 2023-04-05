from typing import Literal, NotRequired, TypedDict

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
