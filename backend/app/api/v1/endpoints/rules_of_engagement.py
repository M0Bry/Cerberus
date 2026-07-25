"""
Rules of Engagement Endpoints — Generate, review, and sign the RoE document.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.rules_of_engagement import (
    DigitalSignatureRequest,
    DigitalSignatureResponse,
    RulesOfEngagementResponse,
)
from app.services.rules_service import RulesService

router = APIRouter()


@router.get("/{engagement_id}", response_model=RulesOfEngagementResponse)
async def get_rules(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the Rules of Engagement document."""
    rules_service = RulesService(db)
    return await rules_service.get_rules(engagement_id, current_user.id)


@router.post("/{engagement_id}/generate", response_model=RulesOfEngagementResponse)
async def generate_rules(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Auto-generate the Rules of Engagement based on the approved scope.
    """
    rules_service = RulesService(db)
    return await rules_service.generate_rules(engagement_id, current_user.id)


@router.post("/{engagement_id}/sign", response_model=DigitalSignatureResponse)
async def sign_rules(
    request: Request,
    engagement_id: str,
    payload: DigitalSignatureRequest,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Digitally sign the Rules of Engagement.

    Requires the user to manually type their full legal name.
    Generates a cryptographic signature and PDF copy.
    """
    rules_service = RulesService(db)
    return await rules_service.sign_rules(
        request, engagement_id, current_user.id, payload
    )
