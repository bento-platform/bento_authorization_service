import itertools
from collections.abc import Callable, Generator, Iterable, Sequence
from datetime import UTC, datetime
from typing import cast

from bento_lib.auth.permissions import PERMISSIONS_BY_STRING, Permission
from bento_lib.search.data_structure import check_ast_against_data_structure
from bento_lib.search.queries import convert_query_to_ast_and_preprocess
from structlog.stdlib import BoundLogger

from ..data_provider.base import BaseDataProvider
from ..idp_manager import BaseIdPManager
from ..json_schemas import TOKEN_DATA
from ..models import (
    BaseIssuerModel,
    GrantModel,
    GroupMembership,
    GroupMembershipExpr,
    GroupMembershipMembers,
    GroupModel,
    IssuerAndClientModel,
    IssuerAndSubjectModel,
    ResourceEverythingModel,
    ResourceModel,
    ResourceSpecificModel,
    StoredGroupModel,
    SubjectEveryoneModel,
    SubjectGroupModel,
    SubjectModel,
)
from .base import PolicyEngine
from .token_data import TokenData

__all__ = [
    "InvalidSubject",
    "DEFAULT_CLIENT_ID_CLAIMS",
    "get_token_client",
    "check_token_against_issuer_based_model_obj",
    "check_if_token_is_in_group",
    "check_if_token_matches_subject",
    "resource_is_equivalent_or_contained",
    "filter_matching_grants",
    "BentoPolicyEngine",
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


class InvalidSubject(Exception):
    pass


# Standard claims holding the token's client ID: azp (OIDC) and client_id (RFC 9068).
DEFAULT_CLIENT_ID_CLAIMS: tuple[str, ...] = ("azp", "client_id")


def get_token_client(
    token_data: TokenData | None, client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS
) -> str | None:
    """
    Get the client ID of a token from the first of the given claims which has a non-empty string value.
    The aud claim is a special case: it is non-standard as a client ID (in RFC 9068, aud is the resource server), but
    some IdPs (e.g., CILogon) only put the client ID there. It is only used if it has a single value.
    :param token_data: Token data (decoded token claims), or None if anonymous.
    :param client_id_claims: Claims to look for the client ID in, in order of priority.
    :return: The client ID, or None if not found.
    """
    td = token_data or {}
    for claim in client_id_claims:
        value = td.get(claim)
        if claim == "aud" and isinstance(value, list):
            value = value[0] if len(value) == 1 else None
        if isinstance(value, str) and value:
            return value
    return None


def check_token_against_issuer_based_model_obj(
    token_data: TokenData | None,
    m: BaseIssuerModel,
    client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS,
) -> bool:
    td = token_data or {}

    if m.iss != td.get("iss"):  # Token issuer isn't the same as this member, so skip this entry early.
        return False

    if isinstance(m, IssuerAndClientModel):
        if m.client == get_token_client(td, client_id_claims):
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
    client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS,
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

    if (g_expiry := group.expiry) is not None and g_expiry <= get_now().astimezone(tz=UTC):
        return False  # Expired group, no membership

    membership: GroupMembership = group.membership

    if isinstance(membership, GroupMembershipMembers):
        # Check if any issuer and (client ID | subject ID) match --> token bearer is a member of this group
        return any(
            check_token_against_issuer_based_model_obj(token_data, member.root, client_id_claims)
            for member in membership.members
        )

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


def _subject_not_implemented(s, logger: BoundLogger) -> NotImplementedError:
    logger.error("can only handle everyone|group|iss+client|iss+sub subjects", subject=s)
    return NotImplementedError(f"Can only handle everyone|group|iss+client|iss+sub subjects but got {s}")


def check_if_token_matches_subject(
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    subject: SubjectModel,
    logger: BoundLogger,
    client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS,
) -> bool:
    # First, check if the subject matches.
    #  - If the grant applies to everyone, it automatically includes the current token/anonymous user.
    #  - Then, check if the grant applies to a specific Group. Then, check if the token is a member of that group.
    #  - Otherwise, check the specifics of the grant to see if there is an issuer/client or issuer/subject match.

    s = subject.root
    if isinstance(s, SubjectEveryoneModel) and s.everyone:
        return True
    elif isinstance(s, SubjectGroupModel):
        if (group_def := groups_dict.get(s.group)) is not None:
            # Will validate group expiry too:
            return check_if_token_is_in_group(token_data, group_def, client_id_claims=client_id_claims)
        logger.error("invalid subject encountered - group not found", subject=subject, group=s.group)
        raise InvalidSubject(str(subject))
    elif isinstance(s, BaseIssuerModel):
        return check_token_against_issuer_based_model_obj(token_data, s, client_id_claims)
    else:
        raise _subject_not_implemented(s, logger)


def _resource_not_implemented(resource_kind, resource_obj, logger: BoundLogger) -> NotImplementedError:
    logger.error(
        "can only handle everything|project-based resources", resource_kind=resource_kind, resource_obj=resource_obj
    )
    return NotImplementedError(
        f"Unimplemented handling for {resource_kind}: {resource_obj} (missing everything|project)"
    )


# TODO: make resource_is_equivalent_or_contained part of a Bento-specific module/class
def resource_is_equivalent_or_contained(
    requested_resource: ResourceModel, grant_resource: ResourceModel, logger: BoundLogger
) -> bool:
    """
    Given two resources, check that the first resource is a sub-resource or equivalent to the second. Be careful,
    order matters a LOT here and screwing it up could impact security.
    :param requested_resource: The first resource; if this resource is a sub-resource or equivalent to the next,
      this function returns True.
    :param grant_resource: The second resource; if this resource is a parent resource or equivalent to the first,
      this function returns True.
    :param logger: Structlog stdlib BoundLogger instance.
    :return: Whether the first (requested) resource is a sub-resource or equivalent to the second (grant) resource.
    """

    # Check if a grant resource matches the requested resource.

    rr = requested_resource.root
    rr_is_everything = isinstance(rr, ResourceEverythingModel)
    gr = grant_resource.root

    # TODO: idea for making this more generic
    #  Have concepts of resources with top-level ID specifier (project) and a list of lists of narrowing parameters
    #  like ("project", ("dataset", "data_type")) as a generic way of representing a resource hierarchy.

    #   - First, if the grant applies to everything. If it does, it automatically matches the specified resource.
    if isinstance(gr, ResourceEverythingModel):
        if rr_is_everything or isinstance(rr, ResourceSpecificModel):
            return True
        raise _resource_not_implemented("resource request", rr, logger)

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
            raise _resource_not_implemented("resource request", rr, logger)

    else:  # grant resource hasn't been implemented in this function
        raise _resource_not_implemented("grant resource", grant_resource, logger)


def filter_matching_grants(
    grants: Sequence[GrantModel],
    groups_dict: dict[int, StoredGroupModel],
    token_data: TokenData | None,
    requested_resource: ResourceModel,
    logger: BoundLogger,
    get_now: Callable[[], datetime] = datetime.now,
    client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS,
) -> Generator[GrantModel, None, None]:
    """
    TODO
    :param grants: List of grants to filter out non-matches.
    :param groups_dict: Dictionary of group IDs and group definitions.
    :param token_data: TODO
    :param requested_resource: TODO
    :param logger: Structlog stdlib BoundLogger instance.
    :param get_now: TODO
    :param client_id_claims: Token claims to read the client ID from, for {iss, client} subjects.
    :return: TODO
    """

    dt_now = get_now().astimezone(tz=UTC)

    for g in grants:
        if g.expiry is not None and g.expiry <= dt_now:
            continue  # Skip expired grants

        try:
            subject_matches: bool = check_if_token_matches_subject(
                groups_dict, token_data, g.subject, logger, client_id_claims
            )
            resource_matches: bool = resource_is_equivalent_or_contained(requested_resource, g.resource, logger)
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


LOG_USER_STR_FIELDS: tuple[str, ...] = ("iss", "azp", "sub")
LOG_SUBJECT_ANONYMOUS = {"anonymous": True}


class BentoPolicyEngine(PolicyEngine):
    def __init__(
        self,
        idp_manager: BaseIdPManager,
        provider: BaseDataProvider,
        jwt_access_tokens: bool = True,
        client_id_claims: Sequence[str] = DEFAULT_CLIENT_ID_CLAIMS,
    ):
        self.idp_manager = idp_manager
        self.provider = provider
        self.jwt_access_tokens = jwt_access_tokens
        self.client_id_claims = tuple(client_id_claims)

    async def _resolve_token_data(self, token: str | None, token_data: TokenData | None) -> TokenData | None:
        """
        Use already-parsed token data if we have it. Otherwise, decode the bearer token, but only if we expect access
        tokens to be JWTs. Opaque tokens give no token data (i.e., the same as anonymous for Bento grants).
        """
        if token_data is not None:
            return token_data
        if token and self.jwt_access_tokens:
            # OIDC / OAuth2 providers do not HAVE to give a JWT access token; there are many caveats here mentioned in
            # https://datatracker.ietf.org/doc/html/rfc9068#name-security-considerations and
            # https://datatracker.ietf.org/doc/html/rfc9068#name-privacy-considerations
            # but here we assume that we get a nice JWT with aud/azp/sub/etc. and they aren't rotating the subject.
            return cast(TokenData, await self.idp_manager.decode(token))
        # TODO: opaque access tokens - resolve token data via the OIDC userinfo endpoint; until then, anonymous for
        #  Bento grants
        return None

    def _determine_permissions(
        self,
        grants: Sequence[GrantModel],
        groups_dict: dict[int, StoredGroupModel],
        token_data: TokenData | None,
        requested_resource: ResourceModel,
        logger: BoundLogger,
    ) -> frozenset[Permission]:
        """
        Private method. Given grant and groip definitions, a token (or None if anonymous), and a resource, return the
        list of permissions the token has on the resource.
        :param grants: A tuple of grants from the database.
        :param groups_dict: A dictionary of {group ID: group definition}
        :param token_data: Parsed token data of a user or automated script, or None if an anonymous request.
        :param requested_resource: The resource the token wishes to operate on.
        :param logger: Structlog stdlib BoundLogger instance.
        :return: The permissions frozen set
        """
        return frozenset(
            itertools.chain.from_iterable(
                _permission_and_gives_from_string(p)
                for g in filter_matching_grants(
                    grants,
                    groups_dict,
                    token_data,
                    requested_resource,
                    logger,
                    client_id_claims=self.client_id_claims,
                )
                for p in g.permissions
            )
        )

    def _evaluate_on_resource_and_permission(
        self,
        grants: Sequence[GrantModel],
        groups_dict: dict[int, StoredGroupModel],
        token_data: TokenData | None,
        resource: ResourceModel,
        permission: Permission,
        logger: BoundLogger,
    ) -> bool:
        # Determine the permissions the token has on the resource
        permissions = self._determine_permissions(grants, groups_dict, token_data, resource, logger)

        # Permitted if our required permission is contained in the permissions this token has on this resource.
        return permission in permissions

    async def determine_permissions_bulk(
        self,
        resources: Sequence[ResourceModel],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[frozenset[Permission]]:
        """
        Given a token (or None if anonymous) and some resources, return the permissions the token has on each resource.
        :param resources: The resources the token wishes to operate on.
        :param token: The bearer token from the request, or None if an anonymous request.
        :param token_data: Parsed token data of a user or automated script, or None if an anonymous request.
        :param logger: Structlog stdlib BoundLogger instance.
        :return: One permissions frozen set per resource, in the same order.
        """

        token_data = await self._resolve_token_data(token, token_data)

        # Fetch grants + groups from the database and any other permissions providers in parallel
        grants, groups_dict = await self.provider.get_grants_and_groups_dict()
        return [self._determine_permissions(grants, groups_dict, token_data, r, logger) for r in resources]

    async def _evaluate_matrix(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[list[bool]]:
        """
        Build the permissions evaluation matrix (rows: resources, columns: permissions) from Bento grants only.
        Does not log the decision; see _log_evaluation.
        """

        # Fetch grants + groups from the database and any other permissions providers in parallel
        grants, groups_dict = await self.provider.get_grants_and_groups_dict()

        return [
            [
                self._evaluate_on_resource_and_permission(grants, groups_dict, token_data, r, p, logger)
                for p in permissions
            ]
            for r in resources
        ]

    async def _log_evaluation(
        self,
        logger: BoundLogger,
        token_data: TokenData | None,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        evaluation_matrix: list[list[bool]],
        **extra,
    ) -> None:
        # Log the decision made, with some user data
        user_str: dict[str, object] = dict(LOG_SUBJECT_ANONYMOUS)
        if token_data is not None:
            # noinspection PyTypedDict
            user_str = {k: token_data.get(k) for k in LOG_USER_STR_FIELDS}
            user_str["client"] = get_token_client(token_data, self.client_id_claims)
        log_obj = {
            "user": user_str,
            "resources": [r.model_dump(mode="json") for r in resources],
            "permissions": permissions,
            "decisions": evaluation_matrix,
            **extra,
        }
        await logger.ainfo("evaluate", log_obj)

    async def evaluate(
        self,
        resources: Sequence[ResourceModel],
        permissions: Sequence[Permission],
        token: str | None,
        token_data: TokenData | None,
        logger: BoundLogger,
    ) -> list[list[bool]]:
        resolved_token_data = await self._resolve_token_data(token, token_data)
        evaluation_matrix = await self._evaluate_matrix(resources, permissions, resolved_token_data, logger)
        await self._log_evaluation(logger, resolved_token_data, resources, permissions, evaluation_matrix)
        return evaluation_matrix
