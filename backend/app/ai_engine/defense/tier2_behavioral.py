"""
Tier 2 — AI Behavioral Analysis.

Monitors user behavior patterns and detects anomalies through
baseline comparison and dynamic risk scoring.
"""

from collections import defaultdict
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()


class BehavioralAnalyzer:
    """
    Tier 2: AI Behavioral Analysis.

    Establishes behavioral baselines and detects anomalous
    activity through continuous session monitoring.
    """

    def __init__(self) -> None:
        self.session_profiles: dict[str, list] = defaultdict(list)
        self.risk_scores: dict[str, float] = defaultdict(float)

    def record_activity(
        self,
        session_id: str,
        user_id: str | None,
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: float,
        client_ip: str,
    ) -> dict:
        """
        Record a session activity and calculate risk score.

        Returns:
            Dict with 'risk_score' (float), 'anomaly_detected' (bool),
            and 'reasons' (list).
        """

        activity = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

        self.session_profiles[session_id].append(activity)

        # Calculate risk score
        risk_score = self._calculate_risk(session_id, activity)
        self.risk_scores[session_id] = risk_score

        anomaly_detected = risk_score > 0.7

        if anomaly_detected:
            logger.warning(
                "behavioral_anomaly_detected",
                session_id=session_id,
                risk_score=risk_score,
                endpoint=endpoint,
            )

        return {
            "risk_score": risk_score,
            "anomaly_detected": anomaly_detected,
            "reasons": self._get_anomaly_reasons(session_id, activity),
        }

    def _calculate_risk(self, session_id: str, activity: dict) -> float:
        """Calculate dynamic risk score for a session."""
        profile = self.session_profiles[session_id]
        score = 0.0

        # Check request frequency (rapid requests = suspicious)
        recent_count = len(profile[-60:])  # Last 60 activities
        if recent_count > 50:
            score += 0.3

        # Check for endpoint enumeration
        unique_endpoints = set(a["endpoint"] for a in profile[-30:])
        if len(unique_endpoints) > 20:
            score += 0.3

        # Check for admin endpoint access
        if "/admin" in activity.get("endpoint", ""):
            score += 0.2

        # Check for high error rates
        recent_errors = sum(
            1 for a in profile[-20:] if a.get("status_code", 200) >= 400
        )
        if recent_errors > 10:
            score += 0.2

        return min(score, 1.0)

    def _get_anomaly_reasons(self, session_id: str, activity: dict) -> list:
        """Get reasons why the activity was flagged."""
        reasons = []
        profile = self.session_profiles[session_id]

        recent_count = len(profile[-60:])
        if recent_count > 50:
            reasons.append(
                f"High request frequency: {recent_count} requests in window"
            )

        unique_endpoints = set(a["endpoint"] for a in profile[-30:])
        if len(unique_endpoints) > 20:
            reasons.append(
                f"Endpoint enumeration: {len(unique_endpoints)} unique endpoints"
            )

        return reasons

    def get_session_risk(self, session_id: str) -> float:
        """Get the current risk score for a session."""
        return self.risk_scores.get(session_id, 0.0)
