"""
Security Utilities — Password Hashing, JWT Tokens, OTP Generation.

All cryptographic operations are handled here to ensure consistent
security practices across the entire platform.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ─── Password Hashing ────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with automatic salt generation."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ─── JWT Token Management ────────────────────────────────────
def create_access_token(
    subject: str | int,
    expires_delta: timedelta | None = None,
    extra_data: dict | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: The token subject (usually user ID).
        expires_delta: Custom expiration time.
        extra_data: Additional claims to include in the token.

    Returns:
        Encoded JWT string.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta  # noqa: UP017
    else:
        expire = datetime.now(timezone.utc) + timedelta(       # noqa: UP017
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "type": "access",
    }
    if extra_data:
        to_encode.update(extra_data)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str | int) -> str:
    """Create a JWT refresh token with extended expiration."""
    expire = datetime.now(timezone.utc) + timedelta(          # noqa: UP017
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict[str, Any] | None:
    """
    Decode and validate a JWT token.

    Returns:
        Decoded payload dict or None if invalid.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError:
        return None


# ─── OTP (One-Time Password) ─────────────────────────────────
def generate_otp(length: int = 6) -> str:
    """
    Generate a cryptographically secure numeric OTP.

    Args:
        length: Number of digits (default 6).

    Returns:
        Numeric OTP string (e.g., "482917").
    """
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp: str) -> str:
    """Hash an OTP using SHA-256 before storage."""
    return hashlib.sha256(otp.encode()).hexdigest()


def verify_otp(plain_otp: str, hashed_otp: str) -> bool:
    """Verify a plain OTP against its SHA-256 hash."""
    return hash_otp(plain_otp) == hashed_otp


# ─── Digital Signature ───────────────────────────────────────
def generate_digital_signature(
    user_id: str,
    engagement_id: str,
    timestamp: datetime,
) -> str:
    """
    Generate a cryptographically protected digital signature
    for Rules of Engagement authorization.

    Returns:
        Hex-encoded signature string.
    """
    payload = f"{user_id}:{engagement_id}:{timestamp.isoformat()}"
    return hashlib.sha256(
        f"{payload}:{settings.SECRET_KEY}".encode()
    ).hexdigest()
