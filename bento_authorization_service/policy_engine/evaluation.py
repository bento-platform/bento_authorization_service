import json

from bento_lib.search.data_structure import check_ast_against_data_structure
from bento_lib.search.queries import convert_query_to_ast_and_preprocess

from typing import Generator, TypedDict

from ..db import Database
from ..idp_manager import BaseIdPManager
from ..json_schemas import TOKEN_DATA
from ..logger import logger
from ..types import Resource, Grant, Group, GroupMembership
from .permissions import Permission


__all__ = [
    "InvalidGrant",
    "InvalidResourceRequest",
    "InvalidGroupMembership",

    "TokenData",

    "check_if_token_is_in_group",
    "check_if_grant_subject_matches_token",
    "check_if_grant_resource_matches_requested_resource",
    "filter_matching_grants",
    "determine_permissions",
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


class InvalidResourceRequest(Exception):
    pass


class InvalidGroupMembership(Exception):
    pass


class TokenData(TypedDict, total=False):
    iss: str
    alg: str
    sub: str
    aud: str
    azp: str  # Will contain client ID
    typ: str

    iat: int
    exp: int


def check_if_token_is_in_group(token_data: TokenData | None, group: Group) -> bool:
    if token_data is None:
        return False  # anonymous users cannot CURRENTLY be part of groups

    membership: GroupMembership = group["membership"]

    if (g_members := membership.get("members")) is not None:
        for member in g_members:
            if "iss" not in member or "alg" not in member:
                raise InvalidGroupMembership()  # No issuer field in member object

            m_iss = member["iss"]
            m_alg = member["alg"]
            t_iss = token_data.get("iss")
            t_alg = token_data.get("alg")

            if (m_client := member.get("client")) is not None:
                if m_iss == t_iss and m_alg == t_alg and m_client == token_data.get("azp"):
                    # Issuer, algorithm, and client IDs match, so this token bearer is a member of this group
                    return True
            elif (m_sub := member.get("sub")) is not None:
                if m_iss == t_iss and m_alg == t_alg and m_sub == token_data.get("sub"):
                    # Issuer, algorithm, and subjects match, so this token bearer is a member of this group
                    return True
            else:
                raise InvalidGroupMembership()  # No client/subject field in member object

        return False

    elif (g_expr := membership.get("expr")) is not None:
        expr_ast = convert_query_to_ast_and_preprocess(g_expr)

        return check_ast_against_data_structure(
            expr_ast,
            token_data,
            schema=TOKEN_DATA,
            internal=True,
            return_all_index_combinations=False,
        )

    else:
        raise InvalidGroupMembership()


def check_if_grant_subject_matches_token(
    groups_dict: dict[int, Group],
    token_data: TokenData | None,
    grant: Grant,
) -> bool:
    t = token_data or {}
    t_iss = t.get("iss")
    t_alg = t.get("alg")

    # First, check if the subject matches.
    #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
    #  - Then, check if the grant applies to a specific Group. Then, check if the token is a member of that group.
    #  - Otherwise, check the specifics of the grant to see if there is an issuer+algorithm/client or issuer+algorithm/subject match.
    if grant["subject"].get("everyone"):
        return True
    elif (group_id := grant["subject"].get("group")) is not None:
        group_def = groups_dict.get(group_id)
        if group_def is None:
            logger.error(f"Invalid grant encountered in database: {grant} (group not found: {group_id})")
            raise InvalidGrant(str(grant))
        return check_if_token_is_in_group(token_data, group_def)
    elif ((g_iss := grant["subject"].get("iss")) and (g_alg := grant["subject"].get("alg"))):
        iss_match: bool = t_iss is not None and g_iss == t_iss
        alg_match: bool = t_alg is not None and g_alg == t_alg
        if g_client := grant["subject"].get("client"):  # {iss, client}
            # g_client is not None by the if-check
            return iss_match and alg_match and g_client == t.get("azp")
        elif g_sub := grant["subject"].get("sub"):
            # g_sub is not None by the if-check
            return iss_match and alg_match and g_sub == t.get("sub")
        else:
            logger.error(f"Invalid grant encountered in database: {grant} (subject has iss but missing azp|sub)")
            raise InvalidGrant(str(grant))
    else:
        logger.error(f"Invalid grant encountered in database: {grant} (subject missing everyone|group|iss)")
        raise InvalidGrant(str(grant))


def check_if_grant_resource_matches_requested_resource(requested_resource: Resource, grant: Grant) -> bool:
    # Check if a grant resource matches the requested resource.
    #   - First, if the grant applies to everything. If it does, it automatically matches the specified resource.

    def _invalid_requested_resource():
        logger.error(f"Invalid resource request: {requested_resource} (missing everything|project)")
        # Missing resource request project or {everything: True}
        raise InvalidResourceRequest(str(requested_resource))

    rr_everything = requested_resource.get("everything")
    rr_project = requested_resource.get("project")

    if grant["resource"].get("everything"):
        if rr_everything or rr_project:
            return True
        _invalid_requested_resource()

    elif g_project := grant["resource"].get("project"):  # we have {project: ..., possibly with dataset, data_type}
        # The grant applies to a project, or dataset, or project data type, or dataset data type.

        g_dataset = grant["resource"].get("dataset")
        g_data_type = grant["resource"].get("data_type")

        if requested_resource.get("everything"):
            # They want access to everything/something node-wide, but this grant is for something specific. No!
            return False
        elif rr_project is not None:
            # The requested resource is at least a project, or possibly more specific:
            #   - project, or
            #   - project + dataset, or
            #   - project + data type

            rr_dataset = requested_resource.get("dataset")
            rr_data_type = requested_resource.get("data_type")

            # Match cases are as follows:
            # projects match AND
            #  - grant dataset is unspecified (i.e., applies to all)
            #       OR grant dataset ID == resource request dataset ID
            # AND
            #  - grant data

            return (
                g_project == rr_project and
                (g_dataset is None or g_dataset == rr_dataset) and
                (g_data_type is None or g_data_type == rr_data_type)
            )
        else:  # requested resource doesn't match any known resource pattern, somehow.
            _invalid_requested_resource()
    else:  # grant resource is invalid
        logger.error(f"Invalid grant encountered in database: {grant} (resource missing everything|project)")
        raise InvalidGrant(str(grant))  # Missing grant project or {everything: True}


def filter_matching_grants(
    grants: tuple[Grant, ...],
    groups_dict: dict[int, Group],
    token_data: TokenData | None,
    requested_resource: Resource,
) -> Generator[Grant, None, None]:
    """
    TODO
    :param grants: List of grants to filter out non-matches.
    :param groups_dict: Dictionary of group IDs and group definitions.
    :param token_data: TODO
    :param requested_resource: TODO
    :return: TODO
    """

    for g in grants:
        subject_matches: bool = check_if_grant_subject_matches_token(groups_dict, token_data, g)
        resource_matches: bool = check_if_grant_resource_matches_requested_resource(requested_resource, g)
        if subject_matches and resource_matches:
            # Grant applies to the token in question, and the requested resource in question, so it is part of the
            # set of grants which determine the permissions the token bearer has on this resource.
            yield g


def determine_permissions(
    grants: tuple[Grant, ...],
    groups_dict: dict[int, Group],
    token_data: TokenData | None,
    requested_resource: Resource,
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
        g["permission"] for g in filter_matching_grants(grants, groups_dict, token_data, requested_resource))


async def evaluate(
    idp_manager: BaseIdPManager,
    db: Database,
    token: str | None,
    requested_resource: Resource,
    required_permissions: frozenset[Permission],
) -> bool:
    # If an access token is specified, validate it and extract its data.
    # OIDC / OAuth2 providers do not HAVE to give a JWT access token; there are many caveats here mentioned in
    # https://datatracker.ietf.org/doc/html/rfc9068#name-security-considerations and
    # https://datatracker.ietf.org/doc/html/rfc9068#name-privacy-considerations
    # but here we assume that we get a nice JWT with aud/azp/sub/etc. and they aren't rotating the subject on us.
    token_data = (await idp_manager.decode(token)) if token else None

    # Determine the permissions
    grants = await db.get_grants()
    groups_dict = await db.get_groups_dict()
    permissions = determine_permissions(grants, groups_dict, token_data, requested_resource)

    # Permitted if all our required permissions are a subset of the permissions this token has on this resource.
    decision = required_permissions.issubset(permissions)

    # Log the decision made, with some user data
    user_str = {"anonymous": True}
    if token_data is not None:
        user_str = {k: token_data.get(k) for k in ("iss", "azp", "sub")}
    log_obj = {"user": user_str, "requested_resource": requested_resource, "decision": decision}
    logger.info(f"evaluate: {json.dumps(log_obj)})")

    return decision
