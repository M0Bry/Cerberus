"""Evidence Tracer — Traces evidence used for AI decisions."""

from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()


class EvidenceTracer:
    """Tracks which evidence was used in AI decision-making."""

    def __init__(self):
        self._traces: dict[str, list[dict]] = {}

    def record(self, decision_id: str, evidence: dict) -> None:
        """Record evidence used for a decision."""
        timestamp = datetime.now(timezone.utc).isoformat()  # noqa: UP017
        self._traces.setdefault(decision_id, []).append({
            "evidence": evidence,
            "timestamp": timestamp,
        })

    def get_trace(self, decision_id: str) -> list[dict]:
        """Get all evidence used for a specific decision."""
        return self._traces.get(decision_id, [])

    def get_summary(self, decision_id: str) -> dict:
        """Get a summary of evidence for a decision."""
        trace = self.get_trace(decision_id)
        sources = {
            e.get("evidence", {}).get("source")
            for e in trace
            if e.get("evidence", {}).get("source")
        }
        return {
            "decision_id": decision_id,
            "evidence_count": len(trace),
            "sources": list(sources),
        }
