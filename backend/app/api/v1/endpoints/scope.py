"""
Scope of Engagement Endpoints — Define and manage testing scope.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.scope import (
    ScopeApprovalResponse,
    ScopeAssetCreate,
    ScopeAssetResponse,
    ScopeResponse,
    ScopeUpdateRequest,
)
from app.services.scope_service import ScopeService

router = APIRouter()


@router.get("/{engagement_id}", response_model=ScopeResponse)
async def get_scope(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the Scope of Engagement for a specific engagement."""
    scope_service = ScopeService(db)
    return await scope_service.get_scope(engagement_id, current_user.id)


@router.put("/{engagement_id}", response_model=ScopeResponse)
async def update_scope(
    engagement_id: str,
    payload: ScopeUpdateRequest,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Update the Scope of Engagement before approval."""
    scope_service = ScopeService(db)
    return await scope_service.update_scope(engagement_id, current_user.id, payload)


@router.post("/{engagement_id}/assets", response_model=ScopeAssetResponse)
async def add_asset(
    engagement_id: str,
    payload: ScopeAssetCreate,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Add an asset to the engagement scope."""
    scope_service = ScopeService(db)
    return await scope_service.add_asset(engagement_id, current_user.id, payload)


@router.post("/{engagement_id}/approve", response_model=ScopeApprovalResponse)
async def approve_scope(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Approve the Scope of Engagement.

    Locks the scope and triggers Rules of Engagement generation.
    """
    scope_service = ScopeService(db)
    return await scope_service.approve_scope(engagement_id, current_user.id)
