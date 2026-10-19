"""
Defense Middleware — Wires all three defense tiers into the request pipeline.

Tier 1: Gateway Protection (InputValidator + RateLimiter)
Tier 2: Behavioral Analysis (IPLogger + AbuseDetector + BehavioralAnalyzer)
Tier 3: Auto Defense (AbuseDetector.block_ip)

الترتيب:
1. استثناء المسارات العامة
2. تسجيل الـ IP (IPLogger)
3. فحص لو الـ IP محظور (AbuseDetector)
4. Rate Limiting (RateLimiter)
5. فحص المدخلات (InputValidator) — أساسي أو متقدم
6. فحص السلوك المسيء (AbuseDetector)
7. Behavioral Analysis (BehavioralAnalyzer) — تسجيل تحذير بس
8. استدعاء الـ endpoint
9. سجل النشاط (BehavioralAnalyzer.record_activity)
10. Security Headers
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.ip_resolver import resolve_client_ip
from app.core.input_validator import (
    validate_request,
    validate_request_advanced,
)
from app.core.rate_limiter import RedisRateLimiter
from app.core.ip_logger import IPLogger
from app.core.abuse_detector import AbuseDetector
from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer
from app.ai_engine.defense.tier3_generative import Tier3GenerativeDefense

logger = structlog.get_logger()

# ─── Tier 3 escalation (fire-and-forget) ────────────────────
# One shared GenerativeDefender for the process. Constructed lazily so
# import time stays cheap and a missing LLM key never blocks startup.
_tier3: Optional[Tier3GenerativeDefense] = None
_tier3_tasks: set = set()
# Cooldown so a flood of blocked requests does not fan out into a
# flood of (potentially LLM-backed) Tier 3 analyses.
_last_tier3: Dict[str, float] = {}
_TIER3_COOLDOWN_SECONDS = 30.0


def _get_tier3() -> Optional[Tier3GenerativeDefense]:
    global _tier3
    if _tier3 is None:
        try:
            _tier3 = Tier3GenerativeDefense()
        except Exception as e:  # pragma: no cover - defensive
            logger.error("defense_middleware_tier3_init_failed", error=str(e))
            return None
    return _tier3


def _maybe_escalate_tier3(
    client_ip: str,
    path: str,
    attack_type: str,
    risk_score: float,
) -> None:
    """
    Trigger a Tier 3 (generative) response in the background.

    Never blocks the request path and never raises: Tier 3 is a
    best-effort responder (virtual patch + alert + optional IP block).
    """
    if not settings.DEFENSE_TIER3_ENABLED:
        return

    now = time.time()
    if now - _last_tier3.get(client_ip, 0.0) < _TIER3_COOLDOWN_SECONDS:
        return
    _last_tier3[client_ip] = now

    defender = _get_tier3()
    if defender is None:
        return

    attack_sequence = [
        {
            "type": attack_type,
            "path": path,
            "timestamp": now,
        }
    ]

    async def _run() -> None:
        try:
            await defender.analyze_and_respond(
                session_id=f"session-{client_ip}",
                client_ip=client_ip,
                attack_sequence=attack_sequence,
                risk_score=risk_score,
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.error("defense_middleware_tier3_run_failed", error=str(e))

    task = asyncio.get_running_loop().create_task(_run())
    _tier3_tasks.add(task)
    task.add_done_callback(_tier3_tasks.discard)


# ─── Metrics Counters ──────────────────────────────────────
_metrics: Dict[str, int] = {
    "requests_inspected": 0,
    "threats_blocked": 0,
    "rate_limit_blocked": 0,
    "input_validation_blocked": 0,
    "advanced_validation_blocked": 0,
    "abuse_blocked": 0,
    "behavioral_anomalies": 0,
    "protocol_blocked": 0,
    "blocked_ips_count": 0,
    "prompt_guard_blocked": 0,
    "prompt_guard_shadow": 0,
}

# ─── Security alert store (Tier 2 Part B — explainability) ───
# Ring buffer of the most recent alert events, newest first. Every
# block/detection point records HERE with the detector's own reasons,
# risk score, and confidence — so the Blue Team console shows WHY
# something was blocked, not just that it was.
MAX_ALERTS = 200
_alerts: list[Dict[str, Any]] = []
_alerts_counter = 0


def record_security_alert(
    *,
    severity: str,
    title: str,
    description: str,
    source_ip: str,
    attack_type: str,
    blocked: bool = True,
    risk_score: Optional[float] = None,
    confidence: Optional[float] = None,
    reasons: Optional[list] = None,
    session: Optional[str] = None,
) -> Dict[str, Any]:
    global _alerts_counter
    _alerts_counter += 1
    alert = {
        "id": f"alert-{_alerts_counter:06d}",
        "severity": severity,
        "title": title,
        "description": description,
        "source_ip": source_ip,
        "attack_type": attack_type,
        "blocked": blocked,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": list(reasons or []),
        "session": session,
        "created_at": datetime.now(timezone.utc),
    }
    _alerts.insert(0, alert)
    if len(_alerts) > MAX_ALERTS:
        _alerts.pop()
    return alert


def get_security_alerts(limit: int = 50) -> list[Dict[str, Any]]:
    return _alerts[:limit]


def get_defense_metrics() -> Dict[str, Any]:
    """
    بترجع إحصائيات الدفاع للـ Dashboard.
    """
    return {
        **_metrics,
        "defense_enabled": settings.DEFENSE_ENABLED,
        "advanced_validation_enabled": settings.ADVANCED_VALIDATION_ENABLED,
        "advanced_validation_threshold": settings.ADVANCED_VALIDATION_THRESHOLD,
        "rate_limit": settings.DEFENSE_RATE_LIMIT,
        "rate_window": settings.DEFENSE_RATE_WINDOW,
        "max_failed_logins": settings.ABUSE_MAX_FAILED_LOGINS,
        "max_403_errors": settings.ABUSE_MAX_403_ERRORS,
    }


# ─── Abuse correlation (post-response) ─────────────────────

_LOGIN_PATH = "/api/v1/auth/login"
_REGISTER_PATH = "/api/v1/auth/register"
_VERIFY_PATHS = ("/api/v1/auth/verify-otp", "/api/v1/auth/resend-otp")
_REFRESH_PATH = "/api/v1/auth/refresh"


async def _correlate_abuse(request: Request, client_ip: str, status_code: int) -> None:
    """
    Feed AbuseDetector counters from the request/response pair.

    - Failed login (401)     -> record_failed_login (per IP + per email)
    - Register attempt (4xx) -> record_register_attempt
    - OTP verify (4xx)       -> record_verify_attempt
    - Any 403 response       -> record_forbidden (403-storm detection)

    This is what makes the brute-force / flooding detection in stages 3
    and 6 actually trigger.
    """
    path = request.url.path

    if status_code == 403:
        await AbuseDetector.record_forbidden(client_ip)

    if request.method != "POST":
        return

    if path == _LOGIN_PATH and status_code == 401:
        email = ""
        try:
            body = await request.json()
            if isinstance(body, dict):
                email = str(body.get("email", ""))[:255]
        except Exception:
            pass
        await AbuseDetector.record_failed_login(client_ip, email)
    elif path == _REGISTER_PATH and 400 <= status_code < 500:
        await AbuseDetector.record_register_attempt(client_ip)
    elif path in _VERIFY_PATHS and 400 <= status_code < 500:
        await AbuseDetector.record_verify_attempt(client_ip)


# ─── Test isolation / ops reset ─────────────────────────────

def reset_defense_state(app) -> None:
    """
    Clear all process-local defense state (in-memory stores, Tier 2
    baselines, Tier 3 escalation cooldowns, middleware metrics).

    Mirrors RateLimitMiddleware.reset_all() so the test-suite can keep
    hermetic isolation. Redis-backed state is not touched.
    """
    from app.core.abuse_detector import AbuseDetector
    from app.core.cost_guard import CostGuard
    from app.core.ip_logger import IPLogger
    from app.core.session_registry import SessionRegistry

    AbuseDetector.reset_all()
    IPLogger.reset_all()
    CostGuard.reset_all()
    SessionRegistry.reset_all()

    _last_tier3.clear()
    _tier3_tasks.clear()
    _alerts.clear()
    for key in list(_metrics):
        _metrics[key] = 0

    # Walk the built middleware stack to reach the live instance.
    node = getattr(app, "middleware_stack", None)
    while node is not None:
        if isinstance(node, DefenseMiddleware):
            node.rate_limiter._fallback.reset_all()
            node.behavioral_analyzer.anomaly_detector._request_patterns.clear()
            node.behavioral_analyzer.session_profiles.clear()
            node.behavioral_analyzer.risk_scores.clear()
            node.behavioral_analyzer.baselines.clear()
            node.behavioral_analyzer.user_session_pairs.clear()
            return
        node = getattr(node, "app", None)


# ─── Middleware ────────────────────────────────────────────

class DefenseMiddleware(BaseHTTPMiddleware):
    """
    Three-tier defense middleware.

    كل HTTP request بيمر على:
    1. IPLogger — تسجيل الـ IP
    2. AbuseDetector — فحص لو الـ IP محظور
    3. RateLimiter — فحص عدد الطلبات
    4. InputValidator — فحص المدخلات (أساسي أو متقدم)
    5. AbuseDetector.is_abusive — فحص السلوك المسيء
    6. BehavioralAnalyzer.analyze — تحليل السلوك (Tier 2)
    7. استدعاء الـ endpoint
    8. BehavioralAnalyzer.record_activity — تسجيل النشاط
    9. Security Headers
    """

    def __init__(self, app):
        super().__init__(app)
        self.rate_limiter = RedisRateLimiter()
        self.behavioral_analyzer = BehavioralAnalyzer()

    # ─── Protocol hardening (Tier 1) ─────────────────────────

    _ALLOWED_METHODS = frozenset(
        {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    )
    _AUTH_PREFIX = "/api/v1/auth"
    _UPLOAD_SUFFIX = "/upload"

    @classmethod
    def _check_protocol_hardening(cls, request: Request) -> Optional[JSONResponse]:
        """
        Cheap, zero-false-positive protocol checks that run BEFORE any
        inspection: method allowlist, Expect-header rejection, and
        body-size caps. Returns a reject response, or None to continue.
        """
        method = request.method
        path = request.url.path

        # a) Method allowlist — TRACE / CONNECT / custom verbs are
        #    rejected before touching the pipeline (Cross-Site Tracing).
        if method not in cls._ALLOWED_METHODS:
            return JSONResponse(
                status_code=405,
                content={
                    "success": False,
                    "error": {"code": 405, "message": "Method not allowed."},
                },
                headers={"Allow": ", ".join(sorted(cls._ALLOWED_METHODS))},
            )

        # b) `Expect: 100-continue` is a classic slow-body DoS trigger
        #    and no legitimate client of this API uses it.
        if request.headers.get("expect", "").lower().strip() == "100-continue":
            return JSONResponse(
                status_code=411,
                content={
                    "success": False,
                    "error": {"code": 411, "message": "Expect header not supported."},
                },
            )

        # c) Body size caps, enforced before validation/handlers run.
        #    Auth payloads are tiny by contract; uploads keep the
        #    documented 50 MB document limit; everything else is JSON.
        if method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if path.startswith(cls._AUTH_PREFIX):
                cap = settings.DEFENSE_MAX_BODY_AUTH_BYTES
                # JSON-only endpoints: a missing Content-Length is not a
                # legal browser request here — reject (also blocks
                # chunked-encoding abuse on credential endpoints).
                if content_length is None:
                    return JSONResponse(
                        status_code=411,
                        content={
                            "success": False,
                            "error": {
                                "code": 411,
                                "message": "Content-Length header is required.",
                            },
                        },
                    )
            elif path.endswith(cls._UPLOAD_SUFFIX):
                cap = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
                # Non-browser upload clients may stream chunked; the
                # document service re-checks the size after read.
            else:
                cap = settings.DEFENSE_MAX_BODY_BYTES
                if content_length is None:
                    return JSONResponse(
                        status_code=411,
                        content={
                            "success": False,
                            "error": {
                                "code": 411,
                                "message": "Content-Length header is required.",
                            },
                        },
                    )

            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "error": {
                                "code": 400,
                                "message": "Invalid Content-Length header.",
                            },
                        },
                    )
                if declared > cap:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "success": False,
                            "error": {
                                "code": 413,
                                "message": "Request body too large.",
                            },
                        },
                    )

        return None

    async def dispatch(self, request: Request, call_next):
        # ─── 0. لو الدفاع مطفي، سيب الطلب يكمل ───
        if not settings.DEFENSE_ENABLED:
            return await call_next(request)

        start_time = time.time()
        path = request.url.path
        # Trusted resolution: the direct TCP peer unless it is one of our
        # own proxies (TRUSTED_PROXY_CIDRS) — X-Forwarded-For from any
        # other peer is client-controllable and is never trusted.
        client_ip = resolve_client_ip(
            request.client.host if request.client else None, request.headers
        )

        # ─── 1. استثناء المسارات العامة ───
        if any(path.startswith(p) for p in settings.DEFENSE_EXCLUDED_PATHS):
            return await call_next(request)

        # ─── 1.5. Protocol hardening: method allowlist / Expect / body size ───
        protocol_reject = self._check_protocol_hardening(request)
        if protocol_reject is not None:
            _metrics["threats_blocked"] += 1
            _metrics["protocol_blocked"] += 1
            logger.warning(
                "defense_middleware_protocol_rejected",
                ip=client_ip,
                path=path,
                method=request.method,
                status=protocol_reject.status_code,
            )
            _pcode = protocol_reject.status_code
            _preface = "Protocol hardening"
            if _pcode == 405:
                _preasons = [
                    f"HTTP method {request.method} not in allowlist "
                    f"(GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS)"
                ]
                _ptitle = f"Disallowed HTTP method: {request.method}"
            elif request.headers.get("expect", "").lower().strip() == "100-continue":
                _preasons = [
                    "Expect: 100-continue rejected (slow-body DoS vector)"
                ]
                _ptitle = "Expect: 100-continue rejected"
            elif _pcode == 413:
                _preasons = ["Request body exceeds the endpoint size cap"]
                _ptitle = "Oversized request body"
            elif _pcode == 411:
                _preasons = ["Missing Content-Length on body-bearing request"]
                _ptitle = "Missing Content-Length"
            else:
                _preasons = ["Malformed Content-Length header"]
                _ptitle = "Invalid Content-Length"
            record_security_alert(
                severity="low",
                title=_ptitle,
                description=f"{_preface}: {_ptitle} on {path}",
                source_ip=client_ip,
                attack_type="protocol_violation",
                risk_score=0.5,
                confidence=0.98,
                reasons=_preasons,
                session=f"ip:{client_ip}",
            )
            return protocol_reject

        _metrics["requests_inspected"] += 1

        # ─── 2. تسجيل الـ IP ───
        try:
            info = IPLogger.extract_client_info(request)
            await IPLogger.log_ip(client_ip, info)
        except Exception as e:
            logger.error("defense_middleware_log_ip_failed", error=str(e), ip=client_ip)

        # ─── 3. فحص لو الـ IP محظور ───
        try:
            if await AbuseDetector.is_blocked(client_ip):
                _metrics["threats_blocked"] += 1
                _metrics["abuse_blocked"] += 1
                logger.warning("defense_middleware_blocked_ip", ip=client_ip, path=path)
                _maybe_escalate_tier3(client_ip, path, "ip_blocked", 0.95)
                record_security_alert(
                    severity="high",
                    title=f"Blocked IP: {client_ip}",
                    description=(
                        f"Request from hard-blocked IP rejected at {path}"
                    ),
                    source_ip=client_ip,
                    attack_type="ip_block",
                    risk_score=0.95,
                    confidence=0.95,
                    reasons=["IP is on the active block list"],
                    session=f"ip:{client_ip}",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "success": False,
                        "error": {
                            "code": 403,
                            "message": "Access denied. Your IP is temporarily blocked.",
                        },
                    },
                )
        except Exception as e:
            logger.error("defense_middleware_is_blocked_failed", error=str(e))

        # ─── 4. Rate Limiting ───
        try:
            rate_result = await self.rate_limiter.check(
                identifier=client_ip,
                scope="ip",
                endpoint=path,
            )
            if not rate_result["allowed"]:
                _metrics["threats_blocked"] += 1
                _metrics["rate_limit_blocked"] += 1
                logger.warning("defense_middleware_rate_limited", ip=client_ip, path=path)
                _maybe_escalate_tier3(client_ip, path, "rate_limit", 0.6)
                record_security_alert(
                    severity="medium",
                    title=f"Rate limit exceeded: {client_ip}",
                    description=(
                        f"IP exceeded {rate_result.get('limit', '?')} requests/window "
                        f"on {path}"
                    ),
                    source_ip=client_ip,
                    attack_type="rate_limit",
                    risk_score=0.6,
                    confidence=0.9,
                    reasons=[
                        f"Rate limit {rate_result.get('limit', '?')}/window exceeded "
                        f"(retry after {rate_result.get('retry_after', '?')}s)"
                    ],
                    session=f"ip:{client_ip}",
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": 429,
                            "message": "Rate limit exceeded. Please try again later.",
                        },
                    },
                    headers={
                        "Retry-After": str(rate_result.get("retry_after", 60)),
                        "X-RateLimit-Limit": str(rate_result.get("limit", 0)),
                        "X-RateLimit-Remaining": str(rate_result.get("remaining", 0)),
                    },
                )
        except Exception as e:
            logger.error("defense_middleware_rate_limit_failed", error=str(e))

        # ─── 4b. Per-user rate limit (Tier 2, Part D) ───
        # IP budgets price NETWORK abuse; this prices ACCOUNT abuse
        # (a compromised/shared account hammering APIs from one IP,
        # or one logged-in user flooding refresh/engagement). The
        # refresh endpoint gets a strict sub-budget.
        if settings.DEFENSE_USER_LIMITS_ENABLED:
            try:
                _uid = self.behavioral_analyzer.extract_user_id(
                    request.headers.get("authorization")
                )
            except Exception:
                _uid = None
            # The /refresh endpoint authenticates via the refresh token
            # in the BODY (no Bearer header), so identify the user from
            # there to apply the per-user refresh sub-budget. Signature
            # is verified; a malformed/foreign token yields no budget.
            if _uid is None and path == _REFRESH_PATH:
                try:
                    _body = await request.body()
                    if _body:
                        _data = json.loads(_body)
                        _rt = (
                            _data.get("refresh_token")
                            if isinstance(_data, dict)
                            else None
                        )
                        if _rt:
                            from app.core.security import decode_token

                            _decoded = decode_token(_rt)
                            if (
                                _decoded
                                and _decoded.get("type") == "refresh"
                            ):
                                _uid = _decoded.get("sub")
                except Exception:  # noqa: BLE001
                    _uid = None
            if _uid:
                _user_limit = (
                    settings.DEFENSE_REFRESH_RATE_LIMIT
                    if path == _REFRESH_PATH
                    else settings.DEFENSE_USER_RATE_LIMIT
                )
                try:
                    ures = await self.rate_limiter.check(
                        identifier=_uid,
                        limit=_user_limit,
                        window=settings.DEFENSE_USER_RATE_WINDOW,
                        scope="user",
                        endpoint=path,
                    )
                    if not ures["allowed"]:
                        _metrics["threats_blocked"] += 1
                        _metrics["rate_limit_blocked"] += 1
                        logger.warning(
                            "defense_middleware_user_rate_limited",
                            ip=client_ip,
                            user_id=_uid,
                            path=path,
                        )
                        record_security_alert(
                            severity="medium",
                            title=f"User rate limit exceeded: {_uid[:8]}",
                            description=(
                                f"Authenticated user exceeded "
                                f"{_user_limit} requests/"
                                f"{settings.DEFENSE_USER_RATE_WINDOW}s "
                                f"on {path}"
                            ),
                            source_ip=client_ip,
                            attack_type="rate_limit",
                            risk_score=0.55,
                            confidence=0.9,
                            reasons=[
                                f"per-user limit {_user_limit}/"
                                f"{settings.DEFENSE_USER_RATE_WINDOW}s "
                                f"exceeded (retry after "
                                f"{ures.get('retry_after', '?')}s)"
                            ],
                            session=f"user:{_uid}",
                        )
                        return JSONResponse(
                            status_code=429,
                            content={
                                "success": False,
                                "error": {
                                    "code": 429,
                                    "message": (
                                        "Rate limit exceeded. Please "
                                        "try again later."
                                    ),
                                },
                            },
                            headers={
                                "Retry-After": str(
                                    ures.get("retry_after", 60)
                                ),
                            },
                        )
                except Exception as e:
                    logger.error(
                        "defense_middleware_user_rate_limit_failed",
                        error=str(e),
                    )

        # ─── 5. فحص المدخلات ───
        try:
            if settings.ADVANCED_VALIDATION_ENABLED:
                # الفحص المتقدم (اختياري)
                advanced_result = await validate_request_advanced(
                    request,
                    threshold=settings.ADVANCED_VALIDATION_THRESHOLD,
                )
                if not advanced_result["valid"]:
                    _metrics["threats_blocked"] += 1
                    _metrics["input_validation_blocked"] += 1
                    _metrics["advanced_validation_blocked"] += 1
                    logger.warning(
                        "defense_middleware_advanced_blocked",
                        ip=client_ip,
                        path=path,
                        worst_field=advanced_result["worst_field"],
                        max_score=advanced_result["max_score"],
                        total_checks=advanced_result["total_checks"],
                    )
                    _adv_score = advanced_result["max_score"] / 100.0
                    record_security_alert(
                        severity="high" if _adv_score >= 0.8 else "medium",
                        title=f"Malicious input blocked: {client_ip}",
                        description=(
                            f"Advanced validation score "
                            f"{advanced_result['max_score']}/100 on field "
                            f"{advanced_result['worst_field']} at {path}"
                        ),
                        source_ip=client_ip,
                        attack_type="input_validation",
                        risk_score=min(0.99, max(0.5, _adv_score)),
                        confidence=_adv_score,
                        reasons=[
                            f"Advanced validation score "
                            f"{advanced_result['max_score']}/100 on "
                            f"{advanced_result['worst_field']}"
                        ],
                        session=f"ip:{client_ip}",
                    )
                    _maybe_escalate_tier3(
                        client_ip,
                        path,
                        "input_validation",
                        min(0.99, max(0.5, advanced_result["max_score"] / 100.0)),
                    )
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "error": {
                                "code": 400,
                                "message": "Request blocked by advanced validation",
                                "field": advanced_result["worst_field"],
                            },
                        },
                    )
            else:
                # الفحص الأساسي (الأصلي)
                await validate_request(request)
        except Exception as e:
            from fastapi import HTTPException
            if isinstance(e, HTTPException):
                _metrics["threats_blocked"] += 1
                _metrics["input_validation_blocked"] += 1
                logger.warning(
                    "defense_middleware_input_blocked",
                    ip=client_ip,
                    path=path,
                    detail=e.detail,
                )
                record_security_alert(
                    severity="high",
                    title=f"Malicious input blocked: {client_ip}",
                    description=f"Input validation rejected request at {path}",
                    source_ip=client_ip,
                    attack_type="input_validation",
                    risk_score=0.7,
                    confidence=0.95,
                    reasons=[f"Validation rule: {e.detail}"],
                    session=f"ip:{client_ip}",
                )
                _maybe_escalate_tier3(client_ip, path, "input_validation", 0.7)
                return JSONResponse(
                    status_code=e.status_code,
                    content={
                        "success": False,
                        "error": {
                            "code": e.status_code,
                            "message": e.detail,
                        },
                    },
                )
            else:
                logger.error("defense_middleware_validation_failed", error=str(e))

        # ─── 5b. Prompt-injection guard (Tier 1, Part C) ───
        # AI-bound chat input is the ONLY user text that reaches the
        # LLM. Graduated response: one plain-text family → shadow
        # alert only (legitimate security discussion must not be
        # blocked); 2+ families, or any family + obfuscation → 400.
        if (
            settings.PROMPT_GUARD_ENABLED
            and request.method == "POST"
            and path.startswith("/api/v1/ai/")
        ):
            try:
                from app.core.prompt_guard import analyze_prompt

                _pg_body = (await request.body())[:120_000]
                _pg = analyze_prompt(_pg_body.decode("utf-8", errors="ignore"))
                if _pg.action == "block":
                    _metrics["threats_blocked"] += 1
                    _metrics["prompt_guard_blocked"] += 1
                    logger.warning(
                        "defense_middleware_prompt_injection_blocked",
                        ip=client_ip,
                        path=path,
                        families=_pg.families,
                        obfuscated=_pg.obfuscated,
                    )
                    # 0.7 = same band as the other heuristic detectors
                    # (input_validation 0.7, rate_limit 0.6): a single
                    # heuristic match must NOT cross
                    # DEFENSE_BLOCK_THRESHOLD (0.8) and auto hard-block
                    # the IP — that is an operational false-positive
                    # risk (a pentest client legitimately discussing
                    # injection techniques). Persistent attacks are
                    # still caught: the block/abuse counters and the
                    # Tier 3 cooldown calibration handle repetition.
                    _maybe_escalate_tier3(client_ip, path, "prompt_injection", 0.7)
                    record_security_alert(
                        severity="high",
                        title=f"Prompt injection blocked: {client_ip}",
                        description=(
                            f"AI-bound message at {path} matches injection "
                            f"families: {', '.join(_pg.families) or 'obfuscation'}"
                            + (" + obfuscation markers" if _pg.obfuscated else "")
                        ),
                        source_ip=client_ip,
                        attack_type="prompt_injection",
                        risk_score=0.9,
                        confidence=0.9,
                        reasons=[f"families: {', '.join(_pg.families)}"]
                        + (["obfuscation markers present"] if _pg.obfuscated else [])
                        + [f"matched: {s}" for s in _pg.matched[:3]],
                        session=f"ip:{client_ip}",
                    )
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "error": {
                                "code": 400,
                                "message": (
                                    "Message blocked by content safety policy. "
                                    "Please rephrase without instruction-override "
                                    "phrasing or encoded payloads."
                                ),
                            },
                        },
                    )
                elif _pg.action == "shadow_alert":
                    _metrics["prompt_guard_shadow"] += 1
                    logger.info(
                        "defense_middleware_prompt_injection_shadow",
                        ip=client_ip,
                        path=path,
                        families=_pg.families,
                        obfuscated=_pg.obfuscated,
                    )
                    record_security_alert(
                        severity="low",
                        title=f"Prompt-injection pattern (shadow): {client_ip}",
                        description=(
                            f"Single-family injection pattern in AI message at "
                            f"{path} ({', '.join(_pg.families) or 'obfuscation only'}) "
                            f"— shadow mode, request passed"
                        ),
                        source_ip=client_ip,
                        attack_type="prompt_injection",
                        blocked=False,
                        risk_score=0.4,
                        confidence=0.55,
                        reasons=[f"shadow: {', '.join(_pg.families)}"]
                        + (["obfuscation markers present"] if _pg.obfuscated else []),
                        session=f"ip:{client_ip}",
                    )
            except Exception as e:
                logger.error("defense_middleware_prompt_guard_failed", error=str(e))

        # ─── 6. فحص السلوك المسيء ───
        try:
            if await AbuseDetector.is_abusive(client_ip, path):
                _metrics["threats_blocked"] += 1
                _metrics["abuse_blocked"] += 1
                logger.warning("defense_middleware_abusive", ip=client_ip, path=path)
                _maybe_escalate_tier3(client_ip, path, "abuse_behavior", 0.8)
                record_security_alert(
                    severity="high",
                    title=f"Abusive behavior: {client_ip}",
                    description=(
                        "IP flagged by abuse detector (failed-login / "
                        "register / verify / 403-storm counters)"
                    ),
                    source_ip=client_ip,
                    attack_type="abuse_behavior",
                    risk_score=0.8,
                    confidence=0.8,
                    reasons=[
                        "Abuse counter threshold exceeded "
                        "(brute force / spray / storm)"
                    ],
                    session=f"ip:{client_ip}",
                )
                # Keep counting a blocked login attempt as abuse, so a
                # persistent attacker still reaches the hard-block
                # threshold (ABUSE_MAX_FAILED_LOGINS * 2) instead of
                # freezing the counter at the first lockout.
                if request.method == "POST" and path == _LOGIN_PATH:
                    await AbuseDetector.record_failed_login(client_ip)
                return JSONResponse(
                    status_code=403,
                    content={
                        "success": False,
                        "error": {
                            "code": 403,
                            "message": "Access denied due to abusive behavior.",
                        },
                    },
                )
        except Exception as e:
            logger.error("defense_middleware_is_abusive_failed", error=str(e))

        # ─── 7. Behavioral Analysis (Tier 2) ───
        # B1: correlate the session with the authenticated user when a
        # token is present — baselines follow the USER across IPs.
        try:
            user_id = self.behavioral_analyzer.extract_user_id(
                request.headers.get("authorization")
            )
        except Exception:
            user_id = None
        try:
            behavioral_result = await self.behavioral_analyzer.analyze(
                client_ip, user_id=user_id
            )
            if behavioral_result.get("is_anomaly"):
                _metrics["behavioral_anomalies"] += 1
                _bscore = float(behavioral_result.get("score", 0.0))
                _breasons = behavioral_result.get("reasons") or [
                    behavioral_result.get("reason", "behavioral_anomaly")
                ]
                logger.warning(
                    "defense_middleware_behavioral_anomaly",
                    ip=client_ip,
                    user_id=user_id,
                    path=path,
                    score=_bscore,
                    method=behavioral_result.get("method"),
                    reasons=_breasons,
                )
                record_security_alert(
                    severity="high" if _bscore >= 0.85 else "medium",
                    title=(
                        f"Behavioral anomaly: "
                        f"{'user ' + user_id if user_id else client_ip}"
                    ),
                    description=(
                        f"Tier-2 risk score {_bscore:.2f} via "
                        f"{behavioral_result.get('method', 'heuristic')} "
                        f"(last path {path})"
                    ),
                    source_ip=client_ip,
                    attack_type="behavioral_anomaly",
                    risk_score=_bscore,
                    confidence=_bscore,
                    reasons=_breasons,
                    session=self.behavioral_analyzer.session_key(
                        client_ip, user_id
                    ),
                )
                # ملاحظة: مش بنحجب الطلب — بنسجل التحذير بس.
                # الحجب مسؤولية AbuseDetector.
        except Exception as e:
            logger.error("defense_middleware_behavioral_failed", error=str(e))

        # ─── 8. استدعاء الـ endpoint ───
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error("defense_middleware_call_next_failed", error=str(e))
            raise

        # ─── 9. سجل النشاط (للـ Behavioral Analysis) ───
        try:
            process_time = time.time() - start_time
            await self.behavioral_analyzer.record_activity(
                client_ip=client_ip,
                endpoint=path,
                method=request.method,
                status_code=response.status_code,
                response_time_ms=process_time * 1000,
                user_id=user_id,
                user_agent=request.headers.get("user-agent"),
            )
        except Exception as e:
            logger.error("defense_middleware_record_activity_failed", error=str(e))

        # ─── 9b. Abuse correlation (post-response) ───
        # Feeds the AbuseDetector counters from real auth outcomes:
        # failed logins, register/verify floods, and 403 storms.
        # This is what makes the brute-force and flooding detection
        # in stage 3/6 actually trigger.
        try:
            await _correlate_abuse(request, client_ip, response.status_code)
        except Exception as e:
            logger.error("defense_middleware_abuse_correlation_failed", error=str(e))

        # ─── 10. Security Headers ───
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # ─── 11. وقت المعالجة ───
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.4f}"

        return response