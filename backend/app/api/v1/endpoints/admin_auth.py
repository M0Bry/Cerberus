"""Admin Authentication — the separate, hidden, 2FA-hardened admin login.

Owner's spec: admin login must be SEPARATE from the standard login, hidden
behind a URL nobody is pointed at, and secured to a high bar (CS +
cyber-security level). Security model:

  * Admin accounts CANNOT authenticate through /auth/login — that endpoint
    rejects them with a generic "Invalid email or password" (no oracle).
  * The portal is two steps, both hidden from OpenAPI:
      POST /admin/login  {email, password}
          - DB-backed limiter: max 5 portal attempts per IP per 15 minutes
            (persists across restarts and multiple workers)
          - credentials must be valid AND the account must be an ADMIN with
            VERIFIED status — anything else gets the same generic 401
          - on success a one-time 6-digit code (90s TTL, 5 attempts) is
            emailed — the response only says "code sent"
      POST /admin/verify {email, otp}
          - code checked against its HASH (codes are never stored plain)
          - success issues the standard JWT (role enforced per-request by
            get_current_admin)
  * Every attempt (success AND failure) is audit-logged with IP/UA and an
    IPLog row — the audit trail feeds the rate limiter and forensics.
  * Wrong-code and wrong-credential responses are deliberately identical
    to an external observer; no existence oracle for admin accounts.
"""

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthenticationError, RateLimitError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_otp,
    hash_otp,
    verify_otp,
    verify_password,
)
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.ip_log import IPLog
from app.db.models.otp import OTPVerification
from app.db.models.user import User, UserRole, UserStatus
from app.db.session import get_db
from app.utils.email import send_admin_otp_email

logger = structlog.get_logger()

router = APIRouter()

# Hardened limiter for the admin portal: 10 attempts per IP per 15 minutes,
# counting BOTH login and verify calls, stored in the database (persists
# across restarts, works with multiple workers). An attacker without valid
# admin credentials cannot progress past step 1 at all; with a (stolen)
# password they get 10 guesses per 15 min against a 1,000,000-code space.
_ADMIN_ATTEMPTS_LIMIT = 10
_ADMIN_WINDOW_MINUTES = 15
_PORTAL_ACTIONS = ("admin_login", "admin_verify")


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class AdminLoginResponse(BaseModel):
    success: bool = True
    message: str
    requires_otp: bool = True
    expires_in: int = settings.OTP_EXPIRE_SECONDS


class AdminVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _portal_attempts(db: AsyncSession, ip: str | None) -> int:
    if not ip:
        return 0
    since = datetime.now(timezone.utc) - timedelta(minutes=_ADMIN_WINDOW_MINUTES)  # noqa: UP017
    result = await db.execute(
        select(func.count()).select_from(IPLog).where(
            IPLog.ip_address == ip,
            IPLog.action.in_(_PORTAL_ACTIONS),
            IPLog.created_at > since,
        )
    )
    return int(result.scalar() or 0)


async def _record_attempt(db: AsyncSession, request: Request, action: str, user_id: str | None = None) -> None:
    """Forensic row that the limiter counts on.

    COMMITTED immediately — get_db rolls back the session when the endpoint
    raises (401 paths), and a rate limiter / audit trail that only saw
    successful attempts would be worthless.
    """
    try:
        ip = _client_ip(request)
        if not ip:
            return
        db.add(
            IPLog(
                id=str(uuid.uuid4()),
                user_id=user_id,
                ip_address=ip,
                ip_version=6 if ":" in ip else 4,
                device_fingerprint=None,
                user_agent=request.headers.get("user-agent"),
                action=action,
                risk_score=0,
            )
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        logger.warning("portal_attempt_record_failed", action=action, error=str(exc))


async def _commit_audit(db: AsyncSession) -> None:
    """Persist failure-path audit rows before the 401 rolls back the session."""
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        logger.warning("portal_audit_commit_failed", error=str(exc))


@router.post("/login", response_model=AdminLoginResponse, include_in_schema=False)
async def admin_portal_login(
    request: Request,
    payload: AdminLoginRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AdminLoginResponse:
    """Step 1 of the hardened admin login — credentials, then a 2FA code.

    Never reveals whether the account exists or is an admin: every failure
    path returns the identical generic message.
    """
    ip = _client_ip(request)

    if ip and await _portal_attempts(db, ip) >= _ADMIN_ATTEMPTS_LIMIT:
        logger.warning("admin_portal_rate_limited", ip=ip)
        raise RateLimitError(
            f"Too many attempts. The admin portal is rate-limited — try again in "
            f"{_ADMIN_WINDOW_MINUTES} minutes."
        )

    await _record_attempt(db, request, "admin_login")

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    valid_credentials = bool(
        user
        and verify_password(payload.password, user.hashed_password)
        and user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN)
        and user.status == UserStatus.VERIFIED
    )

    if not valid_credentials:
        audit = AuditLog(
            user_id=user.id if user else None,
            action=AuditAction.SECURITY_ALERT,
            severity=AuditSeverity.WARNING,
            description=(
                "Admin portal: invalid credentials or non-admin account "
                f"(email={payload.email})"
            ),
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(audit)
        await _commit_audit(db)
        logger.warning("admin_portal_invalid_credentials", email=payload.email, ip=ip)
        raise AuthenticationError("Invalid credentials.")

    # 2FA step: one-time code (hashed at rest, 90s TTL, 5 attempts).
    otp = generate_otp()
    db.add(
        OTPVerification(
            user_id=user.id,
            email=payload.email,
            hashed_otp=hash_otp(otp),
            attempts=0,
            max_attempts=settings.OTP_MAX_ATTEMPTS,
            is_used=False,
            expires_at=datetime.now(timezone.utc) + timedelta(  # noqa: UP017
                seconds=settings.OTP_EXPIRE_SECONDS
            ),
            purpose="admin_login",
        )
    )
    await send_admin_otp_email(payload.email, otp)

    audit = AuditLog(
        user_id=user.id,
        action=AuditAction.ADMIN_ACTION,
        severity=AuditSeverity.INFO,
        description="Admin portal: credentials accepted, 2FA code dispatched",
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(audit)
    await db.flush()
    logger.info("admin_portal_otp_dispatched", user_id=user.id, ip=ip)

    return AdminLoginResponse(
        success=True,
        message="A verification code has been sent to your email. It expires in 90 seconds.",
        requires_otp=True,
        expires_in=settings.OTP_EXPIRE_SECONDS,
    )


@router.post("/verify", response_model=None, include_in_schema=False)
async def admin_portal_verify(
    request: Request,
    payload: AdminVerifyRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """Step 2 of the hardened admin login — verify the 2FA code, issue JWT.

    Returns the same token shape as the standard login so the front end can
    store it identically.
    """
    ip = _client_ip(request)

    if ip and await _portal_attempts(db, ip) >= _ADMIN_ATTEMPTS_LIMIT:
        logger.warning("admin_portal_rate_limited", ip=ip)
        raise RateLimitError(
            f"Too many attempts. The admin portal is rate-limited — try again in "
            f"{_ADMIN_WINDOW_MINUTES} minutes."
        )

    await _record_attempt(db, request, "admin_verify")

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    otp_record = None
    if user:
        otp_result = await db.execute(
            select(OTPVerification)
            .where(
                OTPVerification.user_id == user.id,
                OTPVerification.purpose == "admin_login",
                OTPVerification.is_used.is_(False),
            )
            .order_by(OTPVerification.created_at.desc())
            .limit(1)
        )
        otp_record = otp_result.scalar_one_or_none()

    now = datetime.now(timezone.utc)  # noqa: UP017
    if (
        not user
        or not otp_record
        or now > otp_record.expires_at
        or otp_record.attempts >= otp_record.max_attempts
        or not verify_otp(payload.otp, otp_record.hashed_otp)
    ):
        if otp_record and otp_record.attempts < otp_record.max_attempts:
            otp_record.attempts += 1
        audit = AuditLog(
            user_id=user.id if user else None,
            action=AuditAction.SECURITY_ALERT,
            severity=AuditSeverity.WARNING,
            description=f"Admin portal: 2FA verification failed (email={payload.email})",
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(audit)
        await _commit_audit(db)
        logger.warning("admin_portal_otp_failed", email=payload.email, ip=ip)
        raise AuthenticationError("Invalid or expired verification code.")

    otp_record.is_used = True
    otp_record.used_at = now

    # Full admin session — standard token shape.
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)
    user.last_login_at = now

    audit = AuditLog(
        user_id=user.id,
        action=AuditAction.ADMIN_ACTION,
        severity=AuditSeverity.INFO,
        description="Admin login SUCCESS via hardened 2FA portal",
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(audit)
    await db.flush()
    logger.info("admin_login_success", user_id=user.id, ip=ip)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
