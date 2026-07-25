"""
API Dependencies — Shared dependencies for route handlers.
"""

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.security import decode_token
from app.db.models.user import User, UserRole, UserStatus
from app.db.session import get_db

security_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),  # noqa: B008
    db: AsyncSession = Depends(get_db),                                     # noqa: B008
) -> User:
    """
    Extract and validate the current authenticated user from the JWT token.

    Raises:
        AuthenticationError: If token is invalid, expired, or user not found.
    """
    token = credentials.credentials
    payload = decode_token(token)

    if payload is None:
        raise AuthenticationError("Invalid or expired token")

    if payload.get("type") != "access":
        raise AuthenticationError("Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Invalid token payload")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise AuthenticationError("User not found")

    if user.status == UserStatus.SUSPENDED:
        raise AuthenticationError("Account suspended")

    if user.status == UserStatus.DELETED:
        raise AuthenticationError("Account deleted")

    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user),  # noqa: B008
) -> User:
    """
    Ensure the current user has admin privileges.

    Raises:
        AuthorizationError: If user is not an admin.
    """
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise AuthorizationError("Admin access required")
    return current_user


async def get_verified_user(
    current_user: User = Depends(get_current_user),  # noqa: B008
) -> User:
    """
    Ensure the current user has a verified email.

    Raises:
        AuthenticationError: If email is not verified.
    """
    if current_user.status != UserStatus.VERIFIED:
        raise AuthenticationError("Email verification required")
    return current_user
