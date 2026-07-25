"""
Red Team Schemas — Request/Response models for Red Team execution.
"""

from datetime import datetime

from pydantic import BaseModel


class RedTeamStartResponse(BaseModel):
    success: bool = True
    message: str = "Red Team execution started."
    engagement_id: str
    status: str


class RedTeamStatusResponse(BaseModel):
    success: bool = True
    engagement_id: str
    status: str
    total_paths: int
    completed_paths: int
    confirmed_vulnerabilities: int
    current_path: str | None
    progress_percentage: int


class RedTeamFindingResponse(BaseModel):
    id: str
    title: str
    description: str
    category: str
    severity: str
    cvss_score: float | None
    affected_assets: str | None
    exploitation_method: str | None
    proof_of_concept: str | None
    remediation_steps: str | None
    discovered_at: datetime

    class Config:
        from_attributes = True


class RedTeamCompletionResponse(BaseModel):
    success: bool = True
    message: str = "Red Team phase completed. Risk assessment will begin."
    engagement_id: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
