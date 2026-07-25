"""
Authentication Schemas — Request/Response models for auth endpoints.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─── Registration ─────────────────────────────────────────────
class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=255)
    company_name: str = Field(..., min_length=1, max_length=255)
    job_title: str = Field(..., min_length=1, max_length=255)
    email: EmailStr
    phone_number: str | None = Field(None, max_length=20)
    company_location: str | None = Field(None, max_length=500)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class RegisterResponse(BaseModel):
    success: bool = True
    message: str = "Registration successful. Please verify your email."
    user_id: str
    email_masked: str  # Partially masked email (e.g., "j***@company.com")


# ─── OTP Verification ─────────────────────────────────────────
class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class VerifyOTPResponse(BaseModel):
    success: bool = True
    message: str = "Email verified successfully. Your account is now active."


# ─── Resend OTP ───────────────────────────────────────────────
class ResendOTPRequest(BaseModel):
    email: EmailStr


class ResendOTPResponse(BaseModel):
    success: bool = True
    message: str = "A new verification code has been sent."
    cooldown_seconds: int


# ─── Login ────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    success: bool = True
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


# ─── Token Refresh ────────────────────────────────────────────
class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    success: bool = True
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


# ─── Logout ───────────────────────────────────────────────────
class LogoutResponse(BaseModel):
    success: bool = True
    message: str = "Logged out successfully."
