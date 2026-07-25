"""
Attack Planning Endpoints — AI-driven attack path analysis.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.attack_path import (
    AttackPathListResponse,
    AttackPathResponse,
    AttackPlanApprovalResponse,
    AttackPlanningStartResponse,
)
from app.services.attack_planning_service import AttackPlanningService

router = APIRouter()


@router.post("/{engagement_id}/analyze", response_model=AttackPlanningStartResponse)
async def start_analysis(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Start attack planning analysis.

    The AI constructs an attack graph from collected intelligence,
    evaluates exploit probability, and identifies attack chains.
    """
    planning_service = AttackPlanningService(db)
    return await planning_service.start_analysis(engagement_id, current_user.id)


@router.get("/{engagement_id}/paths", response_model=AttackPathListResponse)
async def get_attack_paths(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all identified attack paths for an engagement."""
    planning_service = AttackPlanningService(db)
    return await planning_service.get_attack_paths(engagement_id, current_user.id)


@router.get("/{engagement_id}/paths/{path_id}", response_model=AttackPathResponse)
async def get_attack_path(
    engagement_id: str,
    path_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get a specific attack path with full technical details."""
    planning_service = AttackPlanningService(db)
    return await planning_service.get_attack_path(
        engagement_id, path_id, current_user.id
    )


@router.post("/{engagement_id}/approve", response_model=AttackPlanApprovalResponse)
async def approve_attack_plan(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Approve the attack plan and begin Red Team execution.
    """
    planning_service = AttackPlanningService(db)
    return await planning_service.approve_plan(engagement_id, current_user.id)
