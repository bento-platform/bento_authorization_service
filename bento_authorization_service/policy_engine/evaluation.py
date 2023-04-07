from typing import Generator, TypedDict

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


class TokenData(TypedDict, total=False):
    iss: str
    sub: str
    aud: str
    azp: str  # Will contain client ID


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

    t_iss = token_data.get("iss")

    t = token_data or {}

    for g in grants:
        subject_matches: bool
        resource_matches: bool = False

        # First, check if the subject matches.
        #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
        #  - Otherwise, check the specifics of the grant to see if there is an issuer/client or issuer/subject match.
        if g["subject"].get("everyone"):
            subject_matches = True
        else:
            g_iss = g["subject"]["iss"]
            iss_match: bool = t_iss is not None and g_iss == t_iss
            if g_client := g["subject"].get("azp"):  # {iss, client}
                # g_client is not None by the if-check
                subject_matches = iss_match and g_client == t.get("azp")
            elif g_sub := g["subject"].get("sub"):
                # g_sub is not None by the if-check
                subject_matches = iss_match and g_sub == t.get("sub")
            else:
                raise InvalidGrant(str(g))

        # Then, check if the resource matches.
        #   - TODO
        if g["resource"].get("everything"):
            resource_matches = True
        else:
            pass  # TODO

        if subject_matches and resource_matches:
            yield g


async def determine_permissions(token: str | None, resource: Resource) -> set[Permission]:
    """
    Given a token (or None if anonymous) and a resource, return the list of permissions the token has on the resource.
    :param token: The token of a user or automated script, or None if an anonymous request.
    :param resource: The resource the token wishes to operate on.
    :return: The permissions
    """
    pass  # TODO


async def evaluate(token: str | None, resource: Resource, required_permissions: set[Permission]) -> bool:
    permissions = await determine_permissions(token, resource)

    # Permitted if all our required permissions are a subset of the permissions this token has on this resource.
    decision = required_permissions.issubset(permissions)

    # TODO: aggressive logging

    return decision
