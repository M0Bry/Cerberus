"""
User Service — Profile management and password changes.
"""

import structlog
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, NotFoundError
from app.core.security import hash_password, verify_password
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.user import User
from app.schemas.user import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    UpdateProfileRequest,
    UserProfileResponse,
)

logger = structlog.get_logger()


class UserService:
    """Handles user profile operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_profile(self, user_id: str) -> UserProfileResponse:
        """Get user profile by ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")
        return UserProfileResponse.model_validate(user)

    async def update_profile(
        self, user_id: str, payload: UpdateProfileRequest
    ) -> UserProfileResponse:
        """Update user profile."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")

        update_data = payload.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)

        await self.db.flush()
        return UserProfileResponse.model_validate(user)

    async def change_password(
        self,
        request: Request,
        user_id: str,
        payload: ChangePasswordRequest,
    ) -> ChangePasswordResponse:
        """Change user password."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")

        if not verify_password(payload.current_password, user.hashed_password):
            raise AuthenticationError("Current password is incorrect")

        user.hashed_password = hash_password(payload.new_password)

        audit = AuditLog(
            user_id=user_id,
            action=AuditAction.PASSWORD_CHANGED,
            severity=AuditSeverity.INFO,
            description="Password changed",
            ip_address=request.client.host if request.client else None,
        )
        self.db.add(audit)
        await self.db.flush()

        logger.info("password_changed", user_id=user_id)
        return ChangePasswordResponse()
