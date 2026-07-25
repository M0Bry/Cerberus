"""
Dashboard Schemas — Request/Response models for dashboard endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class DashboardStatItem(BaseModel):
    label: str
    value: int
    icon: str | None = None
    trend: str | None = None


class RecentAssessmentItem(BaseModel):
    id: str
    engagement_number: str
    project_name: str
    organization_name: str
    status: str
    progress_percentage: int
    risk_level: str | None
    created_at: datetime


class DashboardOverviewResponse(BaseModel):
    success: bool = True
    user_name: str
    organization_name: str
    stats: list[DashboardStatItem]
    recent_assessments: list[RecentAssessmentItem]
    last_assessment_date: datetime | None


class DashboardStatsResponse(BaseModel):
    success: bool = True
    total_assessments: int
    completed_assessments: int
    running_assessments: int
    generated_reports: int
    critical_vulnerabilities: int
    last_assessment_date: datetime | None
