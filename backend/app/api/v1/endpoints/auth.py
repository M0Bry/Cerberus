"""
Authentication Endpoints — Registration, Email Verification, Login, Token Refresh.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
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
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    request: Request,
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Register a new user account.

    Collects user and organization details, validates inputs,
    hashes the password, stores registration metadata, and
    sends a verification OTP to the registered email.
    """
    auth_service = AuthService(db)
    return await auth_service.register(request, payload)


@router.post("/verify-otp", response_model=VerifyOTPResponse)
async def verify_otp(
    request: Request,
    payload: VerifyOTPRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Verify email with OTP code.

    Validates the submitted OTP against the stored hash,
    checks expiration, and activates the user account.
    """
    auth_service = AuthService(db)
    return await auth_service.verify_otp(request, payload)


@router.post("/resend-otp", response_model=ResendOTPResponse)
async def resend_otp(
    request: Request,
    payload: ResendOTPRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Resend verification OTP email.

    Generates a new OTP and sends it to the user's email.
    Enforces a cooldown period between requests.
    """
    auth_service = AuthService(db)
    return await auth_service.resend_otp(request, payload)


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Authenticate user and create a session.

    Validates credentials, checks email verification status,
    records login metadata, and returns JWT tokens.
    """
    auth_service = AuthService(db)
    return await auth_service.login(request, payload)


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Refresh an expired access token using a valid refresh token.
    """
    auth_service = AuthService(db)
    return await auth_service.refresh_token(payload)


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """
    Invalidate the current session and log out the user.
    """
    auth_service = AuthService(db)
    return await auth_service.logout(request)
