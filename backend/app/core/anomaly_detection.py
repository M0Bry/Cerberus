"""
Anomaly Detection — ML-based behavioral anomaly detection for requests.
"""

import time
from collections import defaultdict

import structlog

logger = structlog.get_logger()


class AnomalyDetector:
    """Detects anomalous behavior patterns using statistical analysis."""

    def __init__(self):
        self._request_patterns: dict[str, list[dict]] = defaultdict(list)
        self._baselines: dict[str, dict] = {}

    def record_request(
        self,
        session_id: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: float,
    ):
        """Record a request for pattern analysis."""
        self._request_patterns[session_id].append({
            "endpoint": endpoint,
            "method": method,
            "status": status_code,
            "time": response_time_ms,
            "timestamp": time.time(),
        })
        # Keep only last 1000 per session
        if len(self._request_patterns[session_id]) > 1000:
            self._request_patterns[session_id] = (
                self._request_patterns[session_id][-1000:]
            )

    def detect_anomaly(self, session_id: str) -> dict:
        """Analyze recent requests for anomalous patterns."""
        patterns = self._request_patterns.get(session_id, [])
        if len(patterns) < 10:
            return {"is_anomaly": False, "score": 0.0, "reasons": []}

        recent = patterns[-50:]
        score = 0.0
        reasons = []

        # Check endpoint diversity (scanning pattern)
        unique_endpoints = len(set(r["endpoint"] for r in recent))
        if unique_endpoints > 30:
            score += 0.4
            reasons.append(f"High endpoint diversity: {unique_endpoints}")

        # Check error rate
        errors = sum(1 for r in recent if r["status"] >= 400)
        error_rate = errors / len(recent)
        if error_rate > 0.5:
            score += 0.3
            reasons.append(f"High error rate: {error_rate:.0%}")

        # Check request frequency
        time_span = recent[-1]["timestamp"] - recent[0]["timestamp"]
        if time_span > 0:
            rps = len(recent) / time_span
            if rps > 10:
                score += 0.3
                reasons.append(f"High request rate: {rps:.1f} req/s")

        return {"is_anomaly": score > 0.6, "score": min(1.0, score), "reasons": reasons}
