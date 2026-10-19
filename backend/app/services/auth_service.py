"""
Authentication Service — Handles registration, verification, login, and token management.
"""

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import Request
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.cost_guard import CostGuard
from app.core.exceptions import (
    AuthenticationError,
    ConflictError,
    OTPError,
    RateLimitError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    hash_password,
    verify_otp,
    verify_password,
)
from app.core.session_registry import SessionRegistry, hash_ua
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.otp import OTPVerification
from app.db.models.user import User, UserRole, UserStatus
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    ResendOTPRequest,
    ResendOTPResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from app.utils.email import send_otp_email
from app.utils.ip_capture import client_ip, record_ip_event
from app.utils.user_agent import parse_user_agent

logger = structlog.get_logger()

# ─── Timing equalizers (anti-enumeration) ─────────────────────
# Unknown-credential paths must cost the SAME as known-credential
# paths, otherwise response timing reveals which emails are
# registered. Precomputed at import time so the first request pays
# no extra latency.
_DUMMY_PASSWORD_HASH: str = hash_password("Cerberus-timing-equalizer-8f3a")
_DUMMY_OTP_HASH: str = hash_otp("000000")


class AuthService:
    """Handles all authentication-related business logic."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Registration ─────────────────────────────────────────
    async def register(
        self, request: Request, payload: RegisterRequest
    ) -> RegisterResponse:
        """Register a new user account."""

        # Check for existing email
        existing = await self.db.execute(
            select(User).where(User.email == payload.email)
        )
        if existing.scalar_one_or_none():
            raise ConflictError("An account with this email already exists")

        # ── Cost-aware limits (Tier 1, Part C) ─────────────────
        # Registration creates an account row AND sends an OTP mail —
        # a real cost. Bound it per-email (email cycling) and per-IP
        # (IP farming). Charged BEFORE the account is created: a
        # rejected attempt must not consume the next attempt's budget.
        eff_ip = client_ip(request) or (
            request.client.host if request.client else None
        )
        ok, retry_after = await CostGuard.charge(
            "register",
            payload.email,
            settings.COST_REGISTER_PER_EMAIL,
        )
        if not ok:
            self._raise_cost_abuse(
                operation="register", identifier=payload.email, ip=eff_ip
            )
            raise RateLimitError(
                "Signup limit reached for this email address. "
                "Please try again later."
            )
        if eff_ip:
            ok, retry_after = await CostGuard.charge(
                "register",
                eff_ip,
                settings.COST_REGISTER_PER_IP,
            )
            if not ok:
                self._raise_cost_abuse(
                    operation="register", identifier=eff_ip, ip=eff_ip
                )
                raise RateLimitError(
                    "Too many signups from this network. "
                    "Please try again later."
                )

        # Parse user agent
        ua_info = parse_user_agent(request.headers.get("user-agent", ""))

        # Create user
        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            full_name=payload.full_name,
            email=payload.email,
            phone_number=payload.phone_number,
            company_name=payload.company_name,
            job_title=payload.job_title,
            company_location=payload.company_location,
            hashed_password=hash_password(payload.password),
            status=UserStatus.PENDING_VERIFICATION,
            registration_ip=request.client.host if request.client else None,
            registration_user_agent=request.headers.get("user-agent"),
            registration_browser=ua_info.get("browser"),
            registration_os=ua_info.get("os"),
            registration_device=ua_info.get("device"),
        )
        self.db.add(user)

        # Generate and send OTP
        otp = generate_otp()
        otp_record = OTPVerification(
            user_id=user_id,
            email=payload.email,
            hashed_otp=hash_otp(otp),
            max_attempts=settings.OTP_MAX_ATTEMPTS,
            expires_at=datetime.now(timezone.utc)  # noqa: UP017
            + timedelta(seconds=settings.OTP_EXPIRE_SECONDS),
        )
        self.db.add(otp_record)

        # Audit log
        audit = AuditLog(
            user_id=user_id,
            action=AuditAction.USER_REGISTERED,
            severity=AuditSeverity.INFO,
            description=f"New user registered: {payload.email}",
            ip_address=request.client.host if request.client else None,
        )
        self.db.add(audit)

        await self.db.flush()

        # Silent forensic capture: IP + approximate location + device
        await record_ip_event(self.db, request, user_id, "registration")

        # Send verification email
        await send_otp_email(payload.email, otp)

        # Mask email for response
        email_parts = payload.email.split("@")
        masked = f"{email_parts[0][:3]}***@{email_parts[1]}"

        logger.info("user_registered", user_id=user_id, email=payload.email)

        return RegisterResponse(
            user_id=user_id,
            email_masked=masked,
        )

    # ─── OTP Verification ─────────────────────────────────────
    async def verify_otp(
        self, request: Request, payload: VerifyOTPRequest
    ) -> VerifyOTPResponse:
        """Verify email with OTP code."""

        # Find user by email
        result = await self.db.execute(
            select(User).where(User.email == payload.email)
        )
        user = result.scalar_one_or_none()
        if not user:
            # Anti-enumeration: an unknown email must be
            # indistinguishable from a wrong/expired code — same
            # status (400), same message, equivalent work (throwaway
            # OTP-hash comparison for uniform timing).
            verify_otp(payload.otp, _DUMMY_OTP_HASH)
            raise OTPError("Invalid verification code.")

        if user.status == UserStatus.VERIFIED:
            # Anti-enumeration: this check runs BEFORE the OTP lookup,
            # so a 200 here would be an email-existence oracle. Same
            # generic 400 as every other failed verification.
            raise OTPError("Invalid verification code.")

        # Find latest unused OTP for REGISTRATION (the hardened admin
        # portal's 2FA codes use purpose="admin_login" and are invisible
        # to this flow — and vice versa).
        # LIMIT 1 is required: after a resend the user has MULTIPLE
        # unused registration rows — scalar_one_or_none() would raise
        # MultipleResultsFound (500) on the first verify. Only the
        # NEWEST code is accepted, which is the desired post-resend
        # behavior (older codes are dead).
        otp_result = await self.db.execute(
            select(OTPVerification)
            .where(
                and_(
                    OTPVerification.user_id == user.id,
                    OTPVerification.is_used.is_(False),
                    OTPVerification.purpose == "registration",
                )
            )
            .order_by(OTPVerification.created_at.desc())
            .limit(1)
        )
        otp_record = otp_result.scalar_one_or_none()

        if not otp_record:
            raise OTPError("No verification code found. Please request a new one.")

        # Check expiration
        if datetime.now(timezone.utc) > otp_record.expires_at:  # noqa: UP017
            raise OTPError("Your verification code has expired. Please request a new one.")

        # Check max attempts
        if otp_record.attempts >= otp_record.max_attempts:
            raise OTPError("Maximum verification attempts exceeded. Please request a new code.")

        # Increment attempts
        otp_record.attempts += 1

        # Verify OTP
        if not verify_otp(payload.otp, otp_record.hashed_otp):
            await self.db.flush()
            raise OTPError("Invalid verification code.")

        # Success — activate account
        user.status = UserStatus.VERIFIED
        user.verified_at = datetime.now(timezone.utc)  # noqa: UP017
        otp_record.is_used = True
        otp_record.used_at = datetime.now(timezone.utc)  # noqa: UP017

        # Audit log
        audit = AuditLog(
            user_id=user.id,
            action=AuditAction.USER_VERIFIED,
            severity=AuditSeverity.INFO,
            description=f"Email verified for: {user.email}",
            ip_address=request.client.host if request.client else None,
        )
        self.db.add(audit)

        await self.db.flush()

        # Silent forensic capture: IP + approximate location + device
        await record_ip_event(self.db, request, user.id, "verification")

        logger.info("user_verified", user_id=user.id)

        return VerifyOTPResponse()

    # ─── Resend OTP ───────────────────────────────────────────
    async def resend_otp(
        self, request: Request, payload: ResendOTPRequest
    ) -> ResendOTPResponse:
        """Resend verification OTP with cooldown enforcement."""

        # ── Cost-aware limits (Tier 1, Part C) ─────────────────
        # Every resend attempt charges the per-IP budget — INCLUDING
        # unknown emails, because probing is itself the cost we are
        # pricing. Exhaustion returns a UNIFORM 429 for every email
        # (no enumeration information leaks through the status code).
        eff_ip = client_ip(request) or (
            request.client.host if request.client else None
        )
        if eff_ip:
            ok, _retry = await CostGuard.charge(
                "resend_otp",
                eff_ip,
                settings.COST_RESEND_PER_IP,
            )
            if not ok:
                self._raise_cost_abuse(
                    operation="resend_otp", identifier=eff_ip, ip=eff_ip
                )
                raise RateLimitError(
                    "Too many code requests from this network. "
                    "Please try again later."
                )

        result = await self.db.execute(
            select(User).where(User.email == payload.email)
        )
        user = result.scalar_one_or_none()
        if not user:
            # Anti-enumeration: respond EXACTLY like a real unverified
            # account (same 200 shape, same message, same cooldown)
            # without sending anything — probing an email address can
            # no longer confirm whether it is registered.
            return ResendOTPResponse(
                cooldown_seconds=settings.OTP_RESEND_COOLDOWN_SECONDS
            )

        if user.status == UserStatus.VERIFIED:
            # Same generic shape as every other resend outcome —
            # confirming "you are verified" would be an enumeration
            # oracle of its own.
            return ResendOTPResponse(
                cooldown_seconds=settings.OTP_RESEND_COOLDOWN_SECONDS
            )

        # Check cooldown (registration codes only).
        # LIMIT 1 is required: a user who has already resended once has
        # MULTIPLE registration OTP rows — scalar_one_or_none() would
        # raise MultipleResultsFound (500) on the second resend.
        last_otp = await self.db.execute(
            select(OTPVerification)
            .where(
                OTPVerification.user_id == user.id,
                OTPVerification.purpose == "registration",
            )
            .order_by(OTPVerification.created_at.desc())
            .limit(1)
        )
        last_record = last_otp.scalar_one_or_none()

        if last_record:
            elapsed = (
                datetime.now(timezone.utc) - last_record.created_at  # noqa: UP017
            ).total_seconds()
            if elapsed < settings.OTP_RESEND_COOLDOWN_SECONDS:
                remaining = int(settings.OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                raise RateLimitError(
                    f"Please wait {remaining} seconds before requesting a new code."
                )

        # Per-email cost budget (3 OTP mails/hour/account).
        # Deliberately a SILENT DROP, not a 429: a permanent 429 for
        # known emails vs 200 for unknown emails would become an
        # enumeration oracle. The response stays byte-identical to a
        # real send; the abuse is only visible to the defense stack
        # via the cost_abuse alert.
        ok, _retry = await CostGuard.charge(
            "resend_otp",
            payload.email,
            settings.COST_RESEND_PER_EMAIL,
        )
        if not ok:
            self._raise_cost_abuse(
                operation="resend_otp",
                identifier=payload.email,
                ip=eff_ip,
            )
            return ResendOTPResponse(
                cooldown_seconds=settings.OTP_RESEND_COOLDOWN_SECONDS
            )

        # Generate new OTP
        otp = generate_otp()
        otp_record = OTPVerification(
            user_id=user.id,
            email=payload.email,
            hashed_otp=hash_otp(otp),
            max_attempts=settings.OTP_MAX_ATTEMPTS,
            expires_at=datetime.now(timezone.utc)  # noqa: UP017
            + timedelta(seconds=settings.OTP_EXPIRE_SECONDS),
        )
        self.db.add(otp_record)
        await self.db.flush()

        await send_otp_email(payload.email, otp)

        logger.info("otp_resent", user_id=user.id)

        return ResendOTPResponse(cooldown_seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)

    # ─── Cost-abuse alerting (Tier 1, Part C) ─────────────────
    def _raise_cost_abuse(
        self, operation: str, identifier: str, ip: str | None
    ) -> None:
        """Record a cost_abuse defense alert for an exhausted cost
        budget. Delegates to CostGuard (best-effort, explainable)."""
        CostGuard.record_abuse_alert(operation, identifier, ip)

    # ─── Login ────────────────────────────────────────────────
    async def login(
        self, request: Request, payload: LoginRequest
    ) -> LoginResponse:
        """Authenticate user and create session."""

        # Find user
        result = await self.db.execute(
            select(User).where(User.email == payload.email)
        )
        user = result.scalar_one_or_none()

        # Verify credentials without revealing which field is wrong —
        # and WITHOUT revealing whether the account exists: unknown
        # emails run a throwaway bcrypt check so both paths take the
        # same time (timing-based account enumeration is closed).
        if user is None:
            # Throwaway bcrypt check = same cost as a real one.
            verify_password(payload.password, _DUMMY_PASSWORD_HASH)
            password_ok = False
        else:
            password_ok = verify_password(payload.password, user.hashed_password)
        if not password_ok:
            audit = AuditLog(
                action=AuditAction.USER_LOGIN_FAILED,
                severity=AuditSeverity.WARNING,
                description=f"Failed login attempt for: {payload.email}",
                ip_address=request.client.host if request.client else None,
            )
            self.db.add(audit)
            await self.db.flush()
            raise AuthenticationError("Invalid email or password")

        # Admin accounts are SEPARATED from the standard login: they can
        # only sign in through the hidden hardened portal
        # (POST /admin/login + /admin/verify with 2FA). The error is the
        # same generic message as a wrong password — no existence oracle.
        if user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
            audit = AuditLog(
                user_id=user.id,
                action=AuditAction.SECURITY_ALERT,
                severity=AuditSeverity.WARNING,
                description="Admin login attempted via the STANDARD endpoint — "
                "admins must use the hardened admin portal",
                ip_address=request.client.host if request.client else None,
            )
            self.db.add(audit)
            await self.db.flush()
            logger.warning("admin_login_via_standard_rejected", user_id=user.id)
            raise AuthenticationError("Invalid email or password")

        # Check verification status
        if user.status == UserStatus.PENDING_VERIFICATION:
            raise AuthenticationError(
                "Your account has not yet been activated. "
                "Please verify your email address before signing in."
            )

        if user.status == UserStatus.DELETED:
            # Deleted accounts cannot authenticate — indistinguishable from
            # bad credentials (no account-existence oracle).
            raise AuthenticationError("Invalid email or password")

        if user.status == UserStatus.SUSPENDED:
            # A trial-expiry suspension must NOT lock the user out of the
            # Billing page — they have to be able to log in and pay.
            # A suspension that happened WITHIN the trial window is a manual
            # admin action and keeps the account blocked.
            from app.api.deps import is_trial_suspension

            if is_trial_suspension(user):
                audit = AuditLog(
                    user_id=user.id,
                    action=AuditAction.SECURITY_ALERT,
                    severity=AuditSeverity.WARNING,
                    description=(
                        "Suspended (trial-expired) account logged in "
                        "— payment path only"
                    ),
                    ip_address=request.client.host if request.client else None,
                )
                self.db.add(audit)
                await self.db.flush()
                logger.warning(
                    "suspended_trial_user_login", user_id=user.id
                )
            else:
                raise AuthenticationError("Account suspended. Contact support.")

        # ── Create tokens (session-bound, Tier 2 Part D) ───────
        # A fresh session id (sid) binds BOTH tokens; the registry
        # tracks it so logout can REVOKE and refresh can ROTATE.
        # Best-effort: a registry failure must never block login.
        sid = str(uuid.uuid4())
        access_token = create_access_token(
            subject=user.id,
            extra_data={"sid": sid, "jti": str(uuid.uuid4())},
        )
        refresh_jti = str(uuid.uuid4())
        refresh_token = create_refresh_token(
            subject=user.id,
            extra_data={"sid": sid, "jti": refresh_jti},
        )
        if settings.SESSION_REGISTRY_ENABLED:
            try:
                evicted = SessionRegistry.register(
                    user.id,
                    sid,
                    refresh_jti,
                    ip=request.client.host if request.client else None,
                    ua_hash=hash_ua(request.headers.get("user-agent")),
                )
                if evicted:
                    logger.info(
                        "session_evicted_max_active",
                        user_id=user.id,
                        evicted_sid=evicted,
                    )
            except Exception as e:  # noqa: BLE001
                logger.error("session_register_failed", error=str(e))

        # Update login timestamp
        user.last_login_at = datetime.now(timezone.utc)  # noqa: UP017

        # Audit log
        audit = AuditLog(
            user_id=user.id,
            action=AuditAction.USER_LOGIN,
            severity=AuditSeverity.INFO,
            description=f"User logged in: {user.email}",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        self.db.add(audit)

        await self.db.flush()

        # Silent forensic capture: IP + approximate location + device
        await record_ip_event(self.db, request, user.id, "login")

        logger.info("user_login", user_id=user.id)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # ─── Token Refresh ────────────────────────────────────────
    async def refresh_token(
        self, payload: RefreshTokenRequest, request: Request | None = None
    ) -> RefreshTokenResponse:
        """Refresh access token using a valid refresh token."""

        decoded = decode_token(payload.refresh_token)
        if not decoded or decoded.get("type") != "refresh":
            raise AuthenticationError("Invalid refresh token")

        user_id = decoded.get("sub")
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or user.status != UserStatus.VERIFIED:
            raise AuthenticationError("Invalid refresh token")

        # ── Session rotation (Tier 2, Part D) ─────────────────
        # Session-bound refresh tokens must (a) belong to an active
        # session and (b) carry the session's CURRENT jti. Presenting
        # an already-rotated (old) refresh token is a replay/hijack
        # indicator — same generic error, but audited.
        sid = decoded.get("sid")
        presented_jti = decoded.get("jti")
        if settings.SESSION_REGISTRY_ENABLED and sid:
            if not SessionRegistry.is_active(user.id, sid):
                raise AuthenticationError("Invalid refresh token")
            current_jti = SessionRegistry.get_jti(user.id, sid)
            if (
                presented_jti
                and current_jti
                and presented_jti != current_jti
            ):
                audit = AuditLog(
                    user_id=user.id,
                    action=AuditAction.SECURITY_ALERT,
                    severity=AuditSeverity.WARNING,
                    description=(
                        "Refresh token replay: an already-rotated "
                        "refresh token was presented (possible "
                        "token theft/replay)"
                    ),
                    ip_address=(
                        request.client.host
                        if request is not None and request.client
                        else None
                    ),
                )
                self.db.add(audit)
                await self.db.flush()
                raise AuthenticationError("Invalid refresh token")

        new_refresh_jti = str(uuid.uuid4())
        if sid:
            access_token = create_access_token(
                subject=user.id,
                extra_data={"sid": sid, "jti": str(uuid.uuid4())},
            )
            refresh_token = create_refresh_token(
                subject=user.id,
                extra_data={"sid": sid, "jti": new_refresh_jti},
            )
            if settings.SESSION_REGISTRY_ENABLED:
                SessionRegistry.rotate_jti(user.id, sid, new_refresh_jti)
        else:
            # Legacy token (no sid — issued before Part D or by the
            # admin portal): keep the old behavior, no binding.
            access_token = create_access_token(subject=user.id)
            refresh_token = create_refresh_token(subject=user.id)

        return RefreshTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # ─── Logout ───────────────────────────────────────────────
    async def logout(
        self, request: Request, user: User, token: str
    ) -> LogoutResponse:
        """Invalidate the current session.

        Tier 2 Part D: the session bound to the presenting access
        token is REVOKED in the registry — the access token and its
        refresh token both stop working immediately. (Before Part D
        this was a no-op: both tokens stayed valid until their JWT
        expiry.)
        """
        if settings.SESSION_REGISTRY_ENABLED:
            try:
                payload = decode_token(token) or {}
                sid = payload.get("sid")
                if sid:
                    revoked = SessionRegistry.revoke(user.id, sid)
                    logger.info(
                        "session_revoked_on_logout",
                        user_id=user.id,
                        revoked=revoked,
                    )
            except Exception as e:  # noqa: BLE001 — never break logout
                logger.error("session_revoke_failed", error=str(e))
        return LogoutResponse()
