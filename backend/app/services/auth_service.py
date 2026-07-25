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
from app.core.exceptions import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
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
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.otp import OTPVerification
from app.db.models.user import User, UserStatus
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
from app.utils.user_agent import parse_user_agent

logger = structlog.get_logger()


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
            + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
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
            raise NotFoundError("User not found")

        if user.status == UserStatus.VERIFIED:
            return VerifyOTPResponse(message="Account is already verified.")

        # Find latest unused OTP
        otp_result = await self.db.execute(
            select(OTPVerification)
            .where(
                and_(
                    OTPVerification.user_id == user.id,
                    OTPVerification.is_used.is_(False),
                )
            )
            .order_by(OTPVerification.created_at.desc())
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

        logger.info("user_verified", user_id=user.id)

        return VerifyOTPResponse()

    # ─── Resend OTP ───────────────────────────────────────────
    async def resend_otp(
        self, request: Request, payload: ResendOTPRequest
    ) -> ResendOTPResponse:
        """Resend verification OTP with cooldown enforcement."""

        result = await self.db.execute(
            select(User).where(User.email == payload.email)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")

        if user.status == UserStatus.VERIFIED:
            return ResendOTPResponse(
                message="Account is already verified.",
                cooldown_seconds=0,
            )

        # Check cooldown
        last_otp = await self.db.execute(
            select(OTPVerification)
            .where(OTPVerification.user_id == user.id)
            .order_by(OTPVerification.created_at.desc())
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

        # Generate new OTP
        otp = generate_otp()
        otp_record = OTPVerification(
            user_id=user.id,
            email=payload.email,
            hashed_otp=hash_otp(otp),
            max_attempts=settings.OTP_MAX_ATTEMPTS,
            expires_at=datetime.now(timezone.utc)  # noqa: UP017
            + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
        )
        self.db.add(otp_record)
        await self.db.flush()

        await send_otp_email(payload.email, otp)

        logger.info("otp_resent", user_id=user.id)

        return ResendOTPResponse(cooldown_seconds=settings.OTP_RESEND_COOLDOWN_SECONDS)

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

        # Verify credentials without revealing which field is wrong
        if not user or not verify_password(payload.password, user.hashed_password):
            audit = AuditLog(
                action=AuditAction.USER_LOGIN_FAILED,
                severity=AuditSeverity.WARNING,
                description=f"Failed login attempt for: {payload.email}",
                ip_address=request.client.host if request.client else None,
            )
            self.db.add(audit)
            await self.db.flush()
            raise AuthenticationError("Invalid email or password")

        # Check verification status
        if user.status == UserStatus.PENDING_VERIFICATION:
            raise AuthenticationError(
                "Your account has not yet been activated. "
                "Please verify your email address before signing in."
            )

        if user.status == UserStatus.SUSPENDED:
            raise AuthenticationError("Account suspended. Contact support.")

        # Create tokens
        access_token = create_access_token(subject=user.id)
        refresh_token = create_refresh_token(subject=user.id)

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

        logger.info("user_login", user_id=user.id)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # ─── Token Refresh ────────────────────────────────────────
    async def refresh_token(self, payload: RefreshTokenRequest) -> RefreshTokenResponse:
        """Refresh access token using a valid refresh token."""

        decoded = decode_token(payload.refresh_token)
        if not decoded or decoded.get("type") != "refresh":
            raise AuthenticationError("Invalid refresh token")

        user_id = decoded.get("sub")
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or user.status != UserStatus.VERIFIED:
            raise AuthenticationError("Invalid refresh token")

        access_token = create_access_token(subject=user.id)
        refresh_token = create_refresh_token(subject=user.id)

        return RefreshTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # ─── Logout ───────────────────────────────────────────────
    async def logout(self, request: Request) -> LogoutResponse:
        """Invalidate current session."""
        # In production, add token JTI to Redis blacklist
        return LogoutResponse()
