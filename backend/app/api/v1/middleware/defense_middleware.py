"""
Defense Middleware — Wires all three defense tiers into the request pipeline.

Tier 1: GatewayProtection — WAF, signature detection on every request
Tier 2: BehavioralAnalyzer — Session risk scoring
Tier 3: AutoDefense — IP blocking, alert generation
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.ai_engine.defense.tier1_gateway import GatewayProtection
from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer
from app.core.auto_defense import AutoDefense

# Singleton instances — shared across all requests
_gateway = GatewayProtection()
_behavioral = BehavioralAnalyzer()
_auto_defense = AutoDefense()

# Metrics counters (in production, use Prometheus)
_metrics: dict[str, int] = {
    "requests_inspected": 0,
    "threats_blocked": 0,
    "tier1_blocked": 0,
    "tier2_escalated": 0,
    "tier3_responded": 0,
}


def get_defense_metrics() -> dict:
    """Return current defense metrics for the dashboard."""
    return {
        **_metrics,
        "blocked_ips": _auto_defense.get_blocked_ips(),
        "active_waf_rules": len(_auto_defense._firewall_rules),
    }


def get_gateway() -> GatewayProtection:
    return _gateway


def get_behavioral() -> BehavioralAnalyzer:
    return _behavioral


def get_auto_defense() -> AutoDefense:
    return _auto_defense


class DefenseMiddleware(BaseHTTPMiddleware):
    """
    Three-tier defense middleware.

    Every HTTP request passes through:
    1. GatewayProtection — WAF signature scan
    2. BehavioralAnalyzer — session risk scoring
    3. AutoDefense — IP blocking if escalated
    """

    # Paths excluded from defense inspection
    EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip exempt paths
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        session_id = request.headers.get("authorization", "anon")[:20]

        _metrics["requests_inspected"] += 1

        # ── Check if IP is blocked ──────────────────────────
        if _auto_defense.is_blocked(client_ip):
            _metrics["threats_blocked"] += 1
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "error": {"code": 403, "message": "Access denied"},
                },
            )

        # ── Tier 1: Gateway Protection ──────────────────────
        body = None
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                body = body_bytes.decode("utf-8", errors="ignore")[:10000]
            except Exception:
                body = ""

        tier1_result = _gateway.inspect_request(
            method=request.method,
            path=path,
            headers=dict(request.headers),
            body=body,
            query_params=dict(request.query_params),
            client_ip=client_ip,
        )

        if not tier1_result.get("allowed", True):
            _metrics["threats_blocked"] += 1
            _metrics["tier1_blocked"] += 1

            # Auto-block repeat offenders
            _auto_defense.block_ip(
                client_ip,
                duration_seconds=3600,
                reason=(
                    "Tier1 blocked: "
                    f"{tier1_result.get('threat_type', 'unknown')}"
                ),
            )

            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "error": {
                        "code": 403,
                        "message": "Request blocked by security gateway",
                    },
                },
            )

        # ── Tier 2: Behavioral Analysis ─────────────────────
        start_time = time.time()
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000

        behavioral_result = _behavioral.record_activity(
            session_id=session_id,
            user_id=None,
            endpoint=path,
            method=request.method,
            status_code=response.status_code,
            response_time_ms=duration_ms,
            client_ip=client_ip,
        )

        if behavioral_result.get("anomaly_detected"):
            _metrics["tier2_escalated"] += 1

            # ── Tier 3: Auto Defense Response ───────────────
            risk_score = behavioral_result.get("risk_score", 0)
            if risk_score > 0.8:
                _metrics["tier3_responded"] += 1
                _auto_defense.block_ip(
                    client_ip,
                    duration_seconds=1800,
                    reason=(
                        "Behavioral anomaly: "
                        f"risk_score={risk_score:.2f}"
                    ),
                )

        return response
