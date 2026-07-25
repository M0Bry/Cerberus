"""
Attack Path Schemas — Request/Response models for attack planning.
"""

from datetime import datetime

from pydantic import BaseModel


class AttackPlanningStartResponse(BaseModel):
    success: bool = True
    message: str = "Attack planning analysis started."
    engagement_id: str
    status: str


class AttackPathStepItem(BaseModel):
    step_number: int
    action: str
    tool: str | None
    result: str | None
    success: bool | None

    class Config:
        from_attributes = True


class AttackPathItem(BaseModel):
    id: str
    name: str
    description: str
    initial_entry_point: str
    expected_impact: str
    technical_feasibility: float
    business_impact: float
    confidence_score: float
    priority: int
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AttackPathListResponse(BaseModel):
    success: bool = True
    engagement_id: str
    total: int
    items: list[AttackPathItem]


class AttackPathResponse(BaseModel):
    success: bool = True
    id: str
    name: str
    description: str
    initial_entry_point: str
    expected_impact: str
    technical_feasibility: float
    business_impact: float
    confidence_score: float
    status: str
    result_summary: str | None
    evidence: str | None
    steps: list[AttackPathStepItem]
    created_at: datetime
    executed_at: datetime | None
    completed_at: datetime | None


class AttackPlanApprovalResponse(BaseModel):
    success: bool = True
    message: str = "Attack plan approved. Red Team execution will begin."
    engagement_id: str
    approved_paths: int
