"""
OSINT Endpoints — Open Source Intelligence gathering and results.

Integrates with the osint_framework for actual intelligence collection.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models.user import User
from app.schemas.osint import (
    KnowledgeGraphResponse,
    OSINTFindingListResponse,
    OSINTFindingResponse,
    OSINTStartResponse,
    OSINTSummaryResponse,
)
from app.services.osint_service import OSINTService

router = APIRouter()


@router.post("/{engagement_id}/start", response_model=OSINTStartResponse)
async def start_osint(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Start the OSINT phase for an engagement.

    Launches background tasks to collect intelligence from:
    - Search engines, DNS records, certificate transparency
    - Breach databases, social media, Git repositories
    - Technology fingerprinting, internet archives

    Uses the osint_framework with parallel plugin execution.
    """
    osint_service = OSINTService(db)
    return await osint_service.start_osint(engagement_id, current_user.id)


@router.get("/{engagement_id}/findings", response_model=OSINTFindingListResponse)
async def get_findings(
    engagement_id: str,
    category: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all OSINT findings for an engagement, optionally filtered by category."""
    osint_service = OSINTService(db)
    # Ensure category is a string for the service call
    category = category or ""
    return await osint_service.get_findings(
        engagement_id, current_user.id, category, page, page_size
    )


@router.get("/{engagement_id}/findings/{finding_id}", response_model=OSINTFindingResponse)
async def get_finding(
    engagement_id: str,
    finding_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get a specific OSINT finding with full details."""
    osint_service = OSINTService(db)
    return await osint_service.get_finding(engagement_id, finding_id, current_user.id)


@router.get("/{engagement_id}/knowledge-graph", response_model=KnowledgeGraphResponse)
async def get_knowledge_graph(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get the dynamically built knowledge graph.

    Returns nodes and edges representing relationships between
    discovered assets, technologies, employees, and services.
    """
    osint_service = OSINTService(db)
    return await osint_service.get_knowledge_graph(engagement_id, current_user.id)


@router.get("/{engagement_id}/summary", response_model=OSINTSummaryResponse)
async def get_osint_summary(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the OSINT phase summary statistics."""
    osint_service = OSINTService(db)
    return await osint_service.get_summary(engagement_id, current_user.id)


@router.post("/{engagement_id}/export")
async def export_results(
    engagement_id: str,
    format: str = Query("json", regex="^(json|csv)$"),
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Export OSINT results in JSON or CSV format."""
    osint_service = OSINTService(db)
    summary = await osint_service.get_summary(engagement_id, current_user.id)
    return {
        "success": True,
        "format": format,
        "engagement_id": engagement_id,
        "data": summary.model_dump(),
    }
