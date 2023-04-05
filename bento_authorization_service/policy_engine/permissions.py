from typing import NewType


class PermissionDefinitionError(Exception):
    pass


Level = NewType("Level", str)

LEVEL_DATASET = Level("dataset")
LEVEL_PROJECT = Level("project")
LEVEL_INSTANCE = Level("instance")

# Levels (applicability): Specifies the minimum (most specific) level at which a permission is applicable
#  - e.g., create:project is not a relevant permission at the project or dataset level, just at the instance level
# In order of most specific to most general:
LEVELS = [
    LEVEL_DATASET,
    LEVEL_PROJECT,
    LEVEL_INSTANCE,
]

PermissionVerb = NewType("PermissionVerb", str)
PermissionNoun = NewType("PermissionNoun", str)


PERMISSIONS: list["Permission"] = []
PERMISSIONS_BY_STRING: dict[str, "Permission"] = {}


class Permission:
    def __init__(self, verb: PermissionVerb, noun: PermissionNoun, min_level_required: Level = LEVEL_DATASET):
        self._verb: PermissionVerb = verb
        self._noun: PermissionNoun = noun
        self._min_level_required: Level = min_level_required

        str_rep = str(self)

        if str_rep in PERMISSIONS_BY_STRING:
            raise PermissionDefinitionError(f"Permission {str_rep} already defined")

        PERMISSIONS.append(self)
        PERMISSIONS_BY_STRING[str_rep] = self

    def __eq__(self, other):
        if isinstance(other, Permission):
            return str(self) == str(other)
        elif isinstance(other, str):
            return str(self) == other
        else:
            return False

    def __str__(self):
        return f"{self._verb}:{self._noun}"


QUERY_VERB = PermissionVerb("query")
DOWNLOAD_VERB = PermissionVerb("download")
VIEW_VERB = PermissionVerb("view")
CREATE_VERB = PermissionVerb("create")
EDIT_VERB = PermissionVerb("edit")
DELETE_VERB = PermissionVerb("delete")
INGEST_VERB = PermissionVerb("ingest")
ANALYZE_VERB = PermissionVerb("analyze")
EXPORT_VERB = PermissionVerb("export")

PROJECT_LEVEL_BOOLEAN = PermissionNoun("project_level_boolean")
DATASET_LEVEL_BOOLEAN = PermissionNoun("dataset_level_boolean")

PROJECT_LEVEL_COUNTS = PermissionNoun("project_level_counts")
DATASET_LEVEL_COUNTS = PermissionNoun("dataset_level_counts")

DATA = PermissionNoun("data")

PROJECT = PermissionNoun("project")
DATASET = PermissionNoun("dataset")

PERMISSIONS_NOUN = PermissionNoun("permissions")

P_QUERY_PROJECT_LEVEL_BOOLEAN = Permission(QUERY_VERB, PROJECT_LEVEL_BOOLEAN, min_level_required=LEVEL_PROJECT)
P_QUERY_DATASET_LEVEL_BOOLEAN = Permission(QUERY_VERB, DATASET_LEVEL_BOOLEAN)

P_QUERY_PROJECT_LEVEL_COUNTS = Permission(QUERY_VERB, PROJECT_LEVEL_COUNTS, min_level_required=LEVEL_PROJECT)
P_QUERY_DATASET_LEVEL_COUNTS = Permission(QUERY_VERB, DATASET_LEVEL_COUNTS)

# Data-level: interacting with data inside of data services... and triggering workflows
P_QUERY_DATA = Permission(QUERY_VERB, DATA)  # query at full access
P_DOWNLOAD_DATA = Permission(DOWNLOAD_VERB, DATA)  # download CSVs, associated DRS objects
P_DELETE_DATA = Permission(DELETE_VERB, DATA)  # clear data from a specific data type
#   - workflow-relevant items: (types of workflows....)
P_INGEST_DATA = Permission(INGEST_VERB, DATA)
P_ANALYZE_DATA = Permission(ANALYZE_VERB, DATA)
P_EXPORT_DATA = Permission(EXPORT_VERB, DATA)

# only {everything: true} (instance-level):
P_CREATE_PROJECT = Permission(CREATE_VERB, PROJECT, min_level_required=LEVEL_INSTANCE)
P_DELETE_PROJECT = Permission(DELETE_VERB, PROJECT, min_level_required=LEVEL_INSTANCE)
# only {everything: true} or {project: ...} (instance- or project-level):
P_EDIT_PROJECT = Permission(EDIT_VERB, PROJECT, min_level_required=LEVEL_PROJECT)
P_CREATE_DATASET = Permission(CREATE_VERB, DATASET, min_level_required=LEVEL_PROJECT)
P_DELETE_DATASET = Permission(DELETE_VERB, DATASET, min_level_required=LEVEL_DATASET)

P_EDIT_DATASET = Permission(EDIT_VERB, DATASET)

# can edit permissions for the resource which granted this permission only:
P_EDIT_PERMISSIONS = Permission(EDIT_VERB, PERMISSIONS_NOUN)
