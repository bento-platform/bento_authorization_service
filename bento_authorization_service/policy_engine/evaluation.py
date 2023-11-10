import asyncio
import itertools
import json

from bento_lib.auth.permissions import PERMISSIONS_BY_STRING, Permission
from bento_lib.search.data_structure import check_ast_against_data_structure
from bento_lib.search.queries import convert_query_to_ast_and_preprocess
from datetime import datetime, timezone

from typing import Callable, Generator, Iterable
from typing_extensions import TypedDict  # TODO: py3.12: remove and uninstall library

from ..db import Database
from ..idp_manager import BaseIdPManager
from ..json_schemas import TOKEN_DATA
from ..models import (
    ResourceEverythingModel,
    ResourceSpecificModel,
    ResourceModel,
    SubjectEveryoneModel,
    SubjectGroupModel,
    SubjectModel,
    BaseIssuerModel,
    IssuerAndClientModel,
    IssuerAndSubjectModel,
    GroupMembership,
    GroupModel,
    StoredGroupModel,
    GroupMembershipExpr,
    GroupMembershipMembers,
    GrantModel,
)
from ..logger import logger


__all__ = [
    "InvalidGrant",
    "InvalidSubject",
    "InvalidResourceRequest",
    "TokenData",
    "check_token_against_issuer_based_model_obj",
    "check_if_token_is_in_group",
    "check_if_token_matches_subject",
    "resource_is_equivalent_or_contained",
    "filter_matching_grants",
    "determine_permissions",
    "evaluate_on_resource_and_permission",
    "evaluate",
]


# Policy evaluation
# Given:
#    - a token
#    - a resource
#    - a list of grants which may or may not apply to a token/resource
#    - the required permissions to access the resource
# - Calculate:
#    - whether the token has the required permissions to access the resource
# - Yield:
#    - a boolean response
#    - a log of the decision made, who the decision was made for (sub/client ID), when, on what, and *why


class InvalidGrant(Exception):
    pass


class InvalidSubject(Exception):
    pass


class InvalidResource(Exception):
    pass


class InvalidRequestedResource(InvalidResource):
    pass


class InvalidGrantResource(InvalidResource):
    pass


class InvalidResourceRequest(Exception):
    pass


class TokenData(TypedDict, total=False):
    iss: str
    sub: str
    aud: str
    azp: str  # Will contain client ID
    typ: str

    iat: int
    exp: int


def check_token_against_issuer_based_model_obj(token_data: TokenData | None, m: BaseIssuerModel) -> bool:
    td = token_data or {}

    if m.iss != td.get("iss"):  # Token issuer isn't the same as this member, so skip this entry early.
        return False

    if isinstance(m, IssuerAndClientModel):
        if m.client == td.get("azp"):
            # Issuer and client IDs match, so this token bearer is a member of this group
            return True
        # Otherwise, do nothing & keep checking members
    elif isinstance(m, IssuerAndSubjectModel):
        if m.sub == td.get("sub"):
            # Issuer and subjects match, so this token bearer is a member of this group
            return True
        # Otherwise, do nothing & keep checking members
    else:
        raise NotImplementedError("Issuer-based object is not one of iss+client | iss+sub")

    return False


def check_if_token_is_in_group(
    token_data: TokenData | None,
    group: GroupModel,
    get_now: Callable[[], datetime] = datetime.now,
) -> bool:
    """
    TODO
    :param token_data: TODO
    :param group: TODO
    :param get_now: TODO
    :return: TODO
    """

    if token_data is None:
        return False  # anonymous users cannot CURRENTLY be part of groups

    if (g_expiry := group.expiry) is not None and g_expiry <= get_now().astimezone(tz=timezone.utc):
        return False  # Expired group, no membership

    membership: GroupMembership = group.membership

    if isinstance(membership, GroupMembershipMembers):
        # Check if any issuer and (client ID | subject ID) match --> token bearer is a member of this group
        return any(check_token_against_issuer_based_model_obj(token_data, member.root) for member in membership.members)

    elif isinstance(membership, GroupMembershipExpr):
        return check_ast_against_data_structure(
            ast=convert_query_to_ast_and_preprocess(membership.expr),
            data_structure=token_data,
            schema=TOKEN_DATA,
            internal=True,
            return_all_index_combinations=False,
        )

    else:
        raise NotImplementedError("Group membership is not one of members[], expr")


def check_if_token_matches_subject(
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    subject: SubjectModel,
) -> bool:
    def _not_implemented(err: str) -> NotImplementedError:
        logger.error(err)
        return NotImplementedError(err)

    # First, check if the subject matches.
    #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
    #  - Then, check if the grant applies to a specific Group. Then, check if the token is a member of that group.
    #  - Otherwise, check the specifics of the grant to see if there is an issuer/client or issuer/subject match.

    s = subject.root
    if isinstance(s, SubjectEveryoneModel) and s.everyone:
        return True
    elif isinstance(s, SubjectGroupModel):
        if (group_def := groups_dict.get(s.group)) is not None:
            return check_if_token_is_in_group(token_data, group_def)  # Will validate group expiry too
        logger.error(f"Invalid subject encountered: {subject} (group not found: {s.group})")
        raise InvalidSubject(str(subject))
    elif isinstance(s, BaseIssuerModel):
        return check_token_against_issuer_based_model_obj(token_data, s)
    else:
        raise _not_implemented(f"Can only handle everyone|group|iss+client|iss+sub subjects but got {s}")


# TODO: make resource_is_equivalent_or_contained part of a Bento-specific module/class
def resource_is_equivalent_or_contained(requested_resource: ResourceModel, grant_resource: ResourceModel) -> bool:
    """
    Given two resources, check that the first resource is a sub-resource or equivalent to the second. Be careful,
    order matters a LOT here and screwing it up could impact security.
    :param requested_resource: The first resource; if this resource is a sub-resource or equivalent to the next,
      this function returns True.
    :param grant_resource: The second resource; if this resource is a parent resource or equivalent to the first,
      this function returns True.
    :return: Whether the first (requested) resource is a sub-resource or equivalent to the second (grant) resource.
    """

    # Check if a grant resource matches the requested resource.

    rr = requested_resource.root
    rr_is_everything = isinstance(rr, ResourceEverythingModel)
    gr = grant_resource.root

    def _not_implemented(unimpl_for: str) -> NotImplementedError:
        err_ = f"Unimplemented handling for {unimpl_for} (missing everything|project)"
        logger.error(err_)
        return NotImplementedError(err_)  # TODO: indicate if requested or grant

    # TODO: idea for making this more generic
    #  Have concepts of resources with top-level ID specifier (project) and a list of lists of narrowing parameters
    #  like ("project", ("dataset", "data_type")) as a generic way of representing a resource hierarchy.

    #   - First, if the grant applies to everything. If it does, it automatically matches the specified resource.
    if isinstance(gr, ResourceEverythingModel):
        if rr_is_everything or isinstance(rr, ResourceSpecificModel):
            return True
        raise _not_implemented(f"resource request: {rr}")

    elif isinstance(gr, ResourceSpecificModel):
        # we have {project: ..., possibly with dataset, data_type}
        # The grant applies to a project, or dataset, or project data type, or dataset data type.

        g_project = gr.project
        g_dataset = gr.dataset
        g_data_type = gr.data_type

        if rr_is_everything:
            # They want access to everything/something node-wide, but this grant is for something specific. No!
            return False
        elif isinstance(rr, ResourceSpecificModel):
            # The requested resource is at least a project, or possibly more specific:
            #   - project, or
            #   - project + dataset, or
            #   - project + data type

            # Match cases are as follows:
            # projects match AND
            #  - grant dataset is unspecified (i.e., applies to all)
            #       OR grant dataset ID == resource request dataset ID
            # AND
            #  - grant data
            return (
                g_project == rr.project
                and (g_dataset is None or g_dataset == rr.dataset)
                and (g_data_type is None or g_data_type == rr.data_type)
            )
        else:  # requested resource doesn't match any known resource pattern, somehow.
            raise _not_implemented(f"resource request: {rr}")

    else:  # grant resource hasn't been implemented in this function
        raise _not_implemented(f"grant resource: {grant_resource}")


def filter_matching_grants(
    grants: tuple[GrantModel, ...],
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    requested_resource: ResourceModel,
    get_now: Callable[[], datetime] = datetime.now,
) -> Generator[GrantModel, None, None]:
    """
    TODO
    :param grants: List of grants to filter out non-matches.
    :param groups_dict: Dictionary of group IDs and group definitions.
    :param token_data: TODO
    :param requested_resource: TODO
    :param get_now: TODO
    :return: TODO
    """

    dt_now = get_now().astimezone(tz=timezone.utc)

    for g in grants:
        if g.expiry is not None and g.expiry <= dt_now:
            continue  # Skip expired grants

        try:
            subject_matches: bool = check_if_token_matches_subject(groups_dict, token_data, g.subject)
            resource_matches: bool = resource_is_equivalent_or_contained(requested_resource, g.resource)
            if subject_matches and resource_matches:
                # Grant applies to the token in question, and the requested resource in question, so it is part of the
                # set of grants which determine the permissions the token bearer has on this resource.
                yield g

        except InvalidSubject:  # already logged; from missing grant - just skip this grant
            pass


def _permission_and_gives_from_string(p: str) -> Iterable[Permission]:
    perm = PERMISSIONS_BY_STRING[p]
    yield perm
    yield from perm.gives


def determine_permissions(
    grants: tuple[GrantModel, ...],
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    requested_resource: ResourceModel,
) -> frozenset[Permission]:
    """
    Given a token (or None if anonymous) and a resource, return the list of permissions the token has on the resource.
    :param grants: TODO
    :param groups_dict: TODO
    :param token_data: Parsed token data of a user or automated script, or None if an anonymous request.
    :param requested_resource: The resource the token wishes to operate on.
    :return: The permissions frozen set
    """

    return frozenset(
        itertools.chain.from_iterable(
            _permission_and_gives_from_string(p)
            for g in filter_matching_grants(grants, groups_dict, token_data, requested_resource)
            for p in g.permissions
        )
    )


LOG_USER_STR_FIELDS: tuple[str, ...] = ("iss", "azp", "sub")


def evaluate_on_resource_and_permission(
    grants: tuple[GrantModel, ...],
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    resource: ResourceModel,
    permission: Permission,
) -> bool:
    # Determine the permissions the token has on the resource
    permissions = determine_permissions(grants, groups_dict, token_data, resource)

    # Permitted if our required permission is contained in the permissions this token has on this resource.
    return permission in permissions


async def evaluate(
    idp_manager: BaseIdPManager,
    db: Database,
    token: str | TokenData | None,
    resources: list[ResourceModel] | tuple[ResourceModel, ...],
    permissions: list[Permission] | tuple[Permission, ...],
) -> tuple[tuple[bool, ...], ...]:
    # If an access token is specified, validate it and extract its data.
    # OIDC / OAuth2 providers do not HAVE to give a JWT access token; there are many caveats here mentioned in
    # https://datatracker.ietf.org/doc/html/rfc9068#name-security-considerations and
    # https://datatracker.ietf.org/doc/html/rfc9068#name-privacy-considerations
    # but here we assume that we get a nice JWT with aud/azp/sub/etc. and they aren't rotating the subject on us.

    # If we instead receive already parsed token data, we just use that instead:
    token_data: TokenData | None = (await idp_manager.decode(token)) if isinstance(token, str) else token

    # Fetch grants + groups from the database in parallel
    grants, groups_dict = await asyncio.gather(db.get_grants(), db.get_groups_dict())

    # Determine the permissions evaluation matrix
    evaluation_matrix = tuple(
        tuple(evaluate_on_resource_and_permission(grants, groups_dict, token_data, r, p) for p in permissions)
        for r in resources
    )

    # Log the decision made, with some user data
    user_str = {"anonymous": True}
    if token_data is not None:
        # noinspection PyTypedDict
        user_str = {k: token_data.get(k) for k in LOG_USER_STR_FIELDS}
    log_obj = {
        "user": user_str,
        "resources": [r.model_dump(mode="json") for r in resources],
        "permissions": permissions,
        "decisions": evaluation_matrix,
    }
    logger.info(f"evaluate: {json.dumps(log_obj)})")

    return evaluation_matrix
