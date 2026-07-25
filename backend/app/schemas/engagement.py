"""
Engagement Schemas — Request/Response models for engagement endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class EngagementCreate(BaseModel):
    project_name: str
    organization_name: str
    objective: str | None = None
    description: str | None = None


class EngagementResponse(BaseModel):
    id: str
    engagement_number: str
    project_name: str
    organization_name: str
    objective: str | None
    status: str
    progress_percentage: int
    current_phase: str | None
    risk_level: str | None
    overall_security_score: float | None
    estimated_duration_days: int | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EngagementListResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    page_size: int
    items: list[EngagementResponse]


class EngagementSummaryResponse(BaseModel):
    success: bool = True
    engagement_id: str
    status: str
    progress_percentage: int
    total_findings: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    osint_findings_count: int
    attack_paths_count: int
    reports_count: int
    overall_security_score: float | None
