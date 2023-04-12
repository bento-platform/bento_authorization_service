from typing import Generator, TypedDict

from ..db import Database
from ..types import Resource, Grant
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


class TokenData(TypedDict, total=False):
    iss: str
    sub: str
    aud: str
    azp: str  # Will contain client ID


def check_if_grant_subject_matches_token(token_data: TokenData | None, grant: Grant) -> bool:
    t = token_data or {}
    t_iss = t.get("iss")

    # First, check if the subject matches.
    #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
    #  - Then, TODO: CHECK GROUPS!
    #  - Otherwise, check the specifics of the grant to see if there is an issuer/client or issuer/subject match.
    if grant["subject"].get("everyone"):
        return True
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
            raise InvalidResourceRequest(str(grant))  # Missing resource request project or {everything: True}
    else:
        raise InvalidGrant(str(grant))  # Missing grant project or {everything: True}


def filter_matching_grants(
    token_data: TokenData | None,
    resource: Resource,
    grants: tuple[Grant, ...],
) -> Generator[Grant, None, None]:
    """
    TODO
    :param token_data:
    :param resource:
    :param grants:
    :return:
    """

    for g in grants:
        subject_matches: bool = check_if_grant_subject_matches_token(token_data, g)
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

    all_grants = await db.get_grants()
    token_data = {} if token else None  # TODO: Parse token JWT string

    return set(g["permission"] for g in filter_matching_grants(token_data, resource, all_grants))


async def evaluate(db: Database, token: str | None, resource: Resource, required_permissions: set[Permission]) -> bool:
    permissions = await determine_permissions(db, token, resource)

    # Permitted if all our required permissions are a subset of the permissions this token has on this resource.
    decision = required_permissions.issubset(permissions)

    # TODO: aggressive logging

    return decision
