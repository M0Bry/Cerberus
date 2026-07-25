"""
Red Team Endpoints — Controlled proof-of-concept vulnerability validation.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.red_team import (
    RedTeamCompletionResponse,
    RedTeamFindingResponse,
    RedTeamStartResponse,
    RedTeamStatusResponse,
)
from app.services.red_team_service import RedTeamService

router = APIRouter()


@router.post("/{engagement_id}/start", response_model=RedTeamStartResponse)
async def start_red_team(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Start Red Team execution.

    Validates each attack path using controlled, non-destructive
    proof-of-concept techniques within the Rules of Engagement.
    """
    red_team_service = RedTeamService(db)
    return await red_team_service.start_execution(engagement_id, current_user.id)


@router.get("/{engagement_id}/status", response_model=RedTeamStatusResponse)
async def get_status(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the current Red Team execution status."""
    red_team_service = RedTeamService(db)
    return await red_team_service.get_status(engagement_id, current_user.id)


@router.get("/{engagement_id}/findings", response_model=list[RedTeamFindingResponse])
async def get_findings(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all confirmed vulnerabilities from Red Team execution."""
    red_team_service = RedTeamService(db)
    return await red_team_service.get_findings(engagement_id, current_user.id)


@router.post("/{engagement_id}/complete", response_model=RedTeamCompletionResponse)
async def complete_red_team(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Mark the Red Team phase as complete and proceed to risk assessment."""
    red_team_service = RedTeamService(db)
    return await red_team_service.complete(engagement_id, current_user.id)
