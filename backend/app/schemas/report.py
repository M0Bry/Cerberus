"""
Report Schemas — Request/Response models for report endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class ReportGenerateResponse(BaseModel):
    success: bool = True
    message: str = "Report generation started."
    report_id: str
    engagement_id: str
    status: str


class ReportItem(BaseModel):
    id: str
    title: str
    version: str
    overall_security_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    status: str
    generated_at: datetime

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    success: bool = True
    engagement_id: str
    reports: list[ReportItem]


class ReportResponse(BaseModel):
    success: bool = True
    id: str
    engagement_id: str
    title: str
    version: str
    overall_security_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    executive_summary: str | None
    methodology: str | None
    detailed_findings: str | None
    remediation_roadmap: str | None
    overall_assessment: str | None
    status: str
    generated_at: datetime
