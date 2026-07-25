"""
Risk Assessment Endpoints — Business impact analysis.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.risk_assessment import (
    AIValidationResponse,
    RiskAssessmentListResponse,
    RiskAssessmentStartResponse,
    RiskSummaryResponse,
)
from app.services.risk_assessment_service import RiskAssessmentService

router = APIRouter()


@router.post("/{engagement_id}/start", response_model=RiskAssessmentStartResponse)
async def start_assessment(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Start risk assessment phase.

    Translates technical vulnerabilities into business risk,
    assigns severity levels, and generates executive briefings.
    """
    risk_service = RiskAssessmentService(db)
    return await risk_service.start_assessment(engagement_id, current_user.id)


@router.get("/{engagement_id}", response_model=RiskAssessmentListResponse)
async def get_assessments(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all risk assessments for an engagement."""
    risk_service = RiskAssessmentService(db)
    return await risk_service.get_assessments(engagement_id, current_user.id)


@router.get("/{engagement_id}/summary", response_model=RiskSummaryResponse)
async def get_risk_summary(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the overall risk summary with severity distribution."""
    risk_service = RiskAssessmentService(db)
    return await risk_service.get_summary(engagement_id, current_user.id)


@router.post("/{engagement_id}/validate", response_model=AIValidationResponse)
async def validate_findings(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Run AI Decision Validation.

    Verifies every finding has supporting evidence and removes
    unsupported conclusions to prevent AI hallucinations.
    """
    risk_service = RiskAssessmentService(db)
    return await risk_service.validate_findings(engagement_id, current_user.id)
