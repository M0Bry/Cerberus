"""
User Profile Endpoints — View and update user profile.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.user import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    UpdateProfileRequest,
    UserProfileResponse,
)
from app.services.user_service import UserService

router = APIRouter()


@router.get("/me", response_model=UserProfileResponse)
async def get_profile(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the current user's profile."""
    user_service = UserService(db)
    return await user_service.get_profile(current_user.id)


@router.put("/me", response_model=UserProfileResponse)
async def update_profile(
    payload: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Update the current user's profile information."""
    user_service = UserService(db)
    return await user_service.update_profile(current_user.id, payload)


@router.post("/me/change-password", response_model=ChangePasswordResponse)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Change the current user's password."""
    user_service = UserService(db)
    return await user_service.change_password(request, current_user.id, payload)
