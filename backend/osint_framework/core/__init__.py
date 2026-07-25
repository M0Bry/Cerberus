"""
OSINT Intelligence Result — Standardized data container for all intelligence findings.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class IntelligenceResult:
    """Standardized result container for all OSINT modules."""
    source: str
    data_type: str
    confidence: float  # 0.0 - 1.0
    raw_data: Any
    processed_data: Any
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()  # noqa: UP017
    )
    metadata: dict[str, Any] = field(default_factory=dict)
    category: str = "general"  # technical, credential, employee, technology, historical_web
    severity: str = "info"  # critical, high, medium, low, info
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Entity:
    """Represents a discovered entity (person, domain, email, etc.)."""
    id: str
    entity_type: str  # person, domain, email, ip, company, technology, username
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    source: str = ""
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()  # noqa: UP017
    )


@dataclass
class Relationship:
    """Represents a relationship between two entities."""
    source_id: str
    target_id: str
    relationship_type: str  # uses, owns, employs, hosts, registered_by, etc.
    weight: float = 1.0
    confidence: float = 0.5
    evidence: str = ""


@dataclass
class IntelligenceReport:
    """Final intelligence report container."""
    report_id: str
    target: str
    target_type: str
    classification: str
    executive_summary: str
    detailed_findings: dict[str, Any]
    entities: list[Entity]
    relationships: list[Relationship]
    risk_assessment: dict[str, Any]
    confidence_level: float
    recommendations: list[str]
    sources: list[str]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()  # noqa: UP017
    )
