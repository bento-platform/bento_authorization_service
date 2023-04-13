from bento_lib.search.data_structure import check_ast_against_data_structure
from bento_lib.search.queries import convert_query_to_ast_and_preprocess

from typing import AsyncGenerator, TypedDict

from ..db import Database
from ..idp_manager import idp_manager
from ..json_schemas import TOKEN_DATA
from ..types import Resource, Grant, Group, GroupMembership
from .permissions import Permission


# Policy evaluation
# Given:
#    - a token
#    - a resource
#    - a list of grants which may or may not apply to a token/resource
#    - the required permissions to access the resource
# - Sort the grants in order of most specific to least secific
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
    sub: str
    aud: str
    azp: str  # Will contain client ID


def check_if_token_is_in_group(token_data: TokenData | None, group: Group) -> bool:
    if token_data is None:
        return False  # anonymous users cannot CURRENTLY be part of groups

    membership: GroupMembership = group["membership"]

    if (g_members := membership.get("members")) is not None:
        for member in g_members:
            m_iss = member["iss"]
            t_iss = token_data.get("iss")
            if (m_client := member["client"]) is not None:
                if m_iss == t_iss and m_client == token_data.get("azp"):
                    # Issuer and client IDs match, so this token bearer is a member of this group
                    return True
            elif (m_sub := member["sub"]) is not None:
                if m_iss == t_iss and m_sub == token_data.get("sub"):
                    # Issuer and subjects match, so this token bearer is a member of this group
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


async def check_if_grant_subject_matches_token(db: Database, token_data: TokenData | None, grant: Grant) -> bool:
    t = token_data or {}
    t_iss = t.get("iss")

    # First, check if the subject matches.
    #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
    #  - Then, TODO: CHECK GROUPS!
    #  - Otherwise, check the specifics of the grant to see if there is an issuer/client or issuer/subject match.
    if grant["subject"].get("everyone"):
        return True
    elif (group_id := grant["subject"].get("group")) is not None:
        group_def = await db.get_group(group_id)
        if group_def is None:
            # TODO: log
            raise InvalidGrant(str(grant))
        return check_if_token_is_in_group(token_data, group_def)
    elif g_iss := grant["subject"].get("iss"):
        iss_match: bool = t_iss is not None and g_iss == t_iss
        if g_client := grant["subject"].get("azp"):  # {iss, client}
            # g_client is not None by the if-check
            return iss_match and g_client == t.get("azp")
        elif g_sub := grant["subject"].get("sub"):
            # g_sub is not None by the if-check
            return iss_match and g_sub == t.get("sub")
        else:
            raise InvalidGrant(str(grant))
    else:
        raise InvalidGrant(str(grant))


def check_if_grant_resource_matches_resource_request(resource: Resource, grant: Grant) -> bool:
    # Check if a grant resource matches the requested resource.
    #   - TODO
    if grant["resource"].get("everything"):
        return True
    elif g_project := grant["resource"].get("project"):  # we have {project: ..., possibly with dataset, data_type}
        g_dataset = grant["resource"].get("dataset")
        g_data_type = grant["resource"].get("data_type")

        if resource.get("everything"):
            return False  # They want access to everything but this grant isn't for everything
        elif r_project := resource.get("project"):
            r_dataset = resource.get("dataset")
            r_data_type = resource.get("data_type")

            # Match cases are as follows:
            # projects match AND
            #  - grant dataset is unspecified (i.e., applies to all)
            #       OR grant dataset ID == resource request dataset ID
            # AND
            #  - grant data

            return (
                g_project == r_project and
                (g_dataset is None or g_dataset == r_dataset) and
                (g_data_type is None or g_data_type == r_data_type)
            )
        else:  # grant resource doesn't match any known resource pattern, somehow.
            # TODO: log
            raise InvalidResourceRequest(str(grant))  # Missing resource request project or {everything: True}
    else:
        # TODO: log
        raise InvalidGrant(str(grant))  # Missing grant project or {everything: True}


async def filter_matching_grants(
    db: Database,
    token_data: TokenData | None,
    resource: Resource,
) -> AsyncGenerator[Grant, None, None]:
    """
    TODO
    :param db:
    :param token_data:
    :param resource:
    :return:
    """

    grants = await db.get_grants()

    for g in grants:
        subject_matches: bool = await check_if_grant_subject_matches_token(db, token_data, g)
        resource_matches: bool = check_if_grant_resource_matches_resource_request(resource, g)
        if subject_matches and resource_matches:
            yield g


async def determine_permissions(db: Database, token: str | None, resource: Resource) -> set[Permission]:
    """
    Given a token (or None if anonymous) and a resource, return the list of permissions the token has on the resource.
    :param db: A database instance.
    :param token: The token of a user or automated script, or None if an anonymous request.
    :param resource: The resource the token wishes to operate on.
    :return: The permissions
    """

    token_data = (await idp_manager.decode(token)) if token else None
    return set(g["permission"] async for g in filter_matching_grants(db, token_data, resource))


async def evaluate(db: Database, token: str | None, resource: Resource, required_permissions: set[Permission]) -> bool:
    permissions = await determine_permissions(db, token, resource)

    # Permitted if all our required permissions are a subset of the permissions this token has on this resource.
    decision = required_permissions.issubset(permissions)

    # TODO: aggressive logging

    return decision
