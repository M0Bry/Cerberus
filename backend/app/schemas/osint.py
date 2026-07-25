"""
OSINT Schemas — Request/Response models for OSINT endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class OSINTStartResponse(BaseModel):
    success: bool = True
    message: str = "OSINT phase started. Intelligence collection in progress."
    engagement_id: str
    status: str


class OSINTFindingItem(BaseModel):
    id: str
    category: str
    title: str
    description: str
    confidence_score: float
    discovered_at: datetime

    class Config:
        from_attributes = True


class OSINTFindingListResponse(BaseModel):
    success: bool = True
    engagement_id: str
    total: int
    page: int
    page_size: int
    items: list[OSINTFindingItem]


class OSINTFindingResponse(BaseModel):
    success: bool = True
    id: str
    category: str
    title: str
    description: str
    evidence: str | None
    source_url: str | None
    confidence_score: float
    raw_data: dict | None
    discovered_at: datetime


class KnowledgeGraphNodeItem(BaseModel):
    id: str
    node_type: str
    label: str
    properties: dict | None


class KnowledgeGraphEdgeItem(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    weight: float


class KnowledgeGraphResponse(BaseModel):
    success: bool = True
    engagement_id: str
    nodes: list[KnowledgeGraphNodeItem]
    edges: list[KnowledgeGraphEdgeItem]


class OSINTSummaryResponse(BaseModel):
    success: bool = True
    engagement_id: str
    total_findings: int
    domains_discovered: int
    technologies_identified: int
    employee_profiles: int
    exposed_services: int
    archived_resources: int
    leaked_credentials: int
    risk_distribution: dict
