"""
API Dependencies — Shared dependencies for route handlers.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.security import decode_token
from app.core.session_registry import SessionRegistry
from app.db.models.user import User, UserRole, UserStatus
from app.db.session import get_db

security_scheme = HTTPBearer()


def is_trial_suspension(user: User) -> bool:
    """True when a SUSPENDED account was suspended by the free-trial rule
    (trial expired, no subscription) — as opposed to a manual admin action.

    Trial suspensions must NOT be hard-locked: the user still needs to log
    in, see the suspension, and reach Billing to pay. Manual suspensions
    keep the full block.
    """
    if user.status != UserStatus.SUSPENDED:
        return False
    created = user.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= created + timedelta(  # noqa: UP017
        days=settings.TRIAL_DAYS
    )


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

    # ── Session revocation gate (Tier 2, Part D) ──────────────
    # Tokens carrying a session id (sid) must reference an ACTIVE
    # session: logout / eviction / max-cap kills the session and
    # every request with its tokens fails from that moment. Tokens
    # without sid (legacy, admin-portal) are unaffected.
    sid = payload.get("sid")
    if sid and settings.SESSION_REGISTRY_ENABLED:
        if not SessionRegistry.is_active(user_id, sid):
            raise AuthenticationError(
                "Session has been revoked. Please sign in again."
            )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise AuthenticationError("User not found")

    if user.status == UserStatus.SUSPENDED and not is_trial_suspension(user):
        # Manual suspension: hard block on every protected endpoint.
        raise AuthenticationError("Account suspended")
    # Trial-expiry suspension passes here on purpose: the account must be
    # able to reach /access, /payments/* and Billing to pay. Operation
    # endpoints (e.g. creating an engagement) enforce the gate themselves.

    if user.status == UserStatus.DELETED:
        raise AuthenticationError("Account deleted")

    return user


async def get_optional_user(
    request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> User | None:
    """
    Best-effort auth: return the user if a valid Bearer token is present,
    otherwise None (public endpoints that want to *link* a sender when
    one happens to be logged in — e.g. the landing 'Contact Us' form).
    """
    auth = request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
    except Exception:  # noqa: BLE001
        return None
    if not payload or payload.get("type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or user.status == UserStatus.DELETED:
        return None
    # Trial-expiry suspensions still link to the account (e.g. their Contact
    # Us submissions stay attributed); manual suspensions detach.
    if user.status == UserStatus.SUSPENDED and not is_trial_suspension(user):
        return None
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
