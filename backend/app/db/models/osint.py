"""
OSINT Models — Findings from Open Source Intelligence gathering.
"""

import enum  # noqa: I001
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class FindingCategory(str, enum.Enum):  # noqa: UP042
    """OSINT finding categories matching the dashboard card colors."""
    TECHNICAL = "technical"          # Blue cards
    CREDENTIAL = "credential"        # Red cards
    EMPLOYEE = "employee"            # Yellow cards
    TECHNOLOGY = "technology"        # Cyan cards
    HISTORICAL_WEB = "historical_web"  # Green cards


class OSINTFinding(Base):
    """Individual OSINT discovery."""

    __tablename__ = "osint_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    # ─── Finding Details ──────────────────────────────────────
    category: Mapped[FindingCategory] = mapped_column(
        Enum(FindingCategory), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)

    # ─── Technical Data ───────────────────────────────────────
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ─── Timestamps ───────────────────────────────────────────
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="osint_findings")


class KnowledgeGraphNode(Base):
    """Node in the AI knowledge graph."""

    __tablename__ = "knowledge_graph_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    node_type: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(String(500), nullable=False)
    properties: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )


class KnowledgeGraphEdge(Base):
    """Edge in the AI knowledge graph."""

    __tablename__ = "knowledge_graph_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    source_node_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("knowledge_graph_nodes.id"), nullable=False
    )
    target_node_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("knowledge_graph_nodes.id"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    properties: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
