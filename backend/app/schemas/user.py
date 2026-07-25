"""
User Schemas — Request/Response models for user profile endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserProfileResponse(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    phone_number: str | None
    company_name: str
    job_title: str
    company_location: str | None
    profile_image_url: str | None
    company_logo_url: str | None
    role: str
    status: str
    mfa_enabled: bool
    created_at: datetime
    verified_at: datetime | None
    last_login_at: datetime | None

    class Config:
        from_attributes = True


class UpdateProfileRequest(BaseModel):
    full_name: str | None = Field(None, min_length=2, max_length=255)
    phone_number: str | None = Field(None, max_length=20)
    company_name: str | None = Field(None, min_length=1, max_length=255)
    job_title: str | None = Field(None, min_length=1, max_length=255)
    company_location: str | None = Field(None, max_length=500)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_new_password: str

    @field_validator("confirm_new_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class ChangePasswordResponse(BaseModel):
    success: bool = True
    message: str = "Password changed successfully."
