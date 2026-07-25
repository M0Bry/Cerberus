"""
Engagement Endpoints — CRUD operations for penetration testing engagements.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.engagement import (
    EngagementCreate,
    EngagementListResponse,
    EngagementResponse,
    EngagementSummaryResponse,
)
from app.services.engagement_service import EngagementService

router = APIRouter()


@router.get("/", response_model=EngagementListResponse)
async def list_engagements(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
    search: str | None = None,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    List all engagements for the current user.

    Supports pagination, filtering by status, and text search.
    """
    engagement_service = EngagementService(db)
    return await engagement_service.list_engagements(
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        status=status,
        search=search,
    )


@router.post("/", response_model=EngagementResponse, status_code=201)
async def create_engagement(
    payload: EngagementCreate,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Create a new penetration testing engagement.

    This is the first step in starting an assessment.
    After creation, the user proceeds to the AI conversation
    to define the scope and requirements.
    """
    engagement_service = EngagementService(db)
    return await engagement_service.create_engagement(
        user_id=current_user.id,
        data=payload.model_dump(),
    )


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get a specific engagement by ID."""
    engagement_service = EngagementService(db)
    return await engagement_service.get_engagement(engagement_id, current_user.id)


@router.get("/{engagement_id}/summary", response_model=EngagementSummaryResponse)
async def get_engagement_summary(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get a summary of an engagement including all phase statistics."""
    engagement_service = EngagementService(db)
    return await engagement_service.get_summary(engagement_id, current_user.id)
