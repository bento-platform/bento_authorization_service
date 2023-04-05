from fastapi import APIRouter

__all__ = ["policy_router"]

policy_router = APIRouter(prefix="/policy")


@policy_router.post("/permissions")
async def list_permissions():
    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}}

    # Given a token and a resource, figure out what permissions the token bearer has on the resource.
    # In general, the below evaluate() function MUST be used unless for cosmetic purposes (UI rendering).

    pass


@policy_router.post("/evaluate")
async def evaluate():
    # Request structure:
    #   Header: Authorization: Bearer <token>
    #   Post body: {resource: {}, requiredPermissions: []}

    # Given a token, a resource, and a list of required permissions, figure out if the
    # Builds on the above method, but here a decision is actually being made.

    pass
