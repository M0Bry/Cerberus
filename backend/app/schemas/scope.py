"""
Scope Schemas — Request/Response models for Scope of Engagement.
"""

from datetime import datetime

from pydantic import BaseModel


class ScopeAssetCreate(BaseModel):
    asset_type: str
    value: str
    description: str | None = None
    is_excluded: bool = False
    exclusion_reason: str | None = None


class ScopeAssetResponse(BaseModel):
    id: str
    asset_type: str
    value: str
    description: str | None
    is_excluded: bool
    exclusion_reason: str | None

    class Config:
        from_attributes = True


class ScopeResponse(BaseModel):
    success: bool = True
    id: str
    engagement_id: str
    summary: str
    testing_objective: str
    testing_period_start: datetime | None
    testing_period_end: datetime | None
    is_non_destructive: bool
    max_impact_level: str | None
    legal_restrictions: str | None
    compliance_requirements: str | None
    include_osint: bool
    include_red_team: bool
    include_risk_assessment: bool
    include_report_generation: bool
    assets: list[ScopeAssetResponse]
    is_approved: bool
    created_at: datetime
    approved_at: datetime | None

    class Config:
        from_attributes = True


class ScopeUpdateRequest(BaseModel):
    summary: str | None = None
    testing_objective: str | None = None
    is_non_destructive: bool | None = None
    max_impact_level: str | None = None
    legal_restrictions: str | None = None
    compliance_requirements: str | None = None
    include_osint: bool | None = None
    include_red_team: bool | None = None
    include_risk_assessment: bool | None = None
    include_report_generation: bool | None = None


class ScopeApprovalResponse(BaseModel):
    success: bool = True
    message: str = "Scope approved. Rules of Engagement will be generated."
    scope_id: str
