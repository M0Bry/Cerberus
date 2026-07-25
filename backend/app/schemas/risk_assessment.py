"""
Risk Assessment Schemas — Request/Response models for risk assessment.
"""

from datetime import datetime

from pydantic import BaseModel


class RiskAssessmentStartResponse(BaseModel):
    success: bool = True
    message: str = "Risk assessment started."
    engagement_id: str
    status: str


class RiskAssessmentItem(BaseModel):
    id: str
    vulnerability_id: str
    vulnerability_title: str
    risk_level: str
    likelihood_of_exploitation: float
    cumulative_risk_score: float
    potential_consequences: dict | None
    remediation_priority: int
    assessed_at: datetime

    class Config:
        from_attributes = True


class RiskAssessmentListResponse(BaseModel):
    success: bool = True
    engagement_id: str
    total: int
    items: list[RiskAssessmentItem]


class RiskAssessmentResponse(BaseModel):
    success: bool = True
    id: str
    vulnerability_id: str
    risk_level: str
    likelihood_of_exploitation: float
    complexity_required: str | None
    privileges_obtainable: str | None
    asset_sensitivity: float
    cumulative_risk_score: float
    potential_consequences: dict | None
    affected_services: str | None
    regulatory_implications: str | None
    remediation_priority: int
    estimated_remediation_effort: str | None
    assessed_at: datetime


class RiskSummaryResponse(BaseModel):
    success: bool = True
    engagement_id: str
    overall_risk_level: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    executive_briefing: str
    most_critical_attack_paths: list[str]


class AIValidationResponse(BaseModel):
    success: bool = True
    engagement_id: str
    total_findings_reviewed: int
    findings_validated: int
    findings_downgraded: int
    findings_excluded: int
    duplicates_removed: int
    message: str = "AI validation completed successfully."
