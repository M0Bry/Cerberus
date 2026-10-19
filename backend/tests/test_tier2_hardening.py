"""Tier-2 hardening (Part B) — regression + behavior tests.

Covers:
  B1  Session identity correlation (JWT-aware session keys, forgery-proof)
  B2  Time-decayed risk signals + z-score baseline deviation
  B3  Explainable security alerts (reasons / risk / confidence)
  B4  Baseline poisoning guard (clean-traffic-only, capped learning)
"""

import time
import uuid

import pytest
from jose import jwt as _jose
from starlette.requests import Request

from app.core.config import settings
from app.core.security import create_access_token
from app.main import app
from app.schemas.defense import SecurityAlertItem
from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer
import app.api.v1.middleware.defense_middleware as dm
from app.services.defense_service import DefenseService


def make_request(method: str = "GET", path: str = "/", headers=None) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
    }
    return Request(scope)


def act(
    endpoint: str,
    status: int,
    age_seconds: float,
    now: float | None = None,
    method: str = "GET",
) -> dict:
    """Build a synthetic profile entry `age_seconds` in the past."""
    now = now if now is not None else time.time()
    return {
        "endpoint": endpoint,
        "method": method,
        "status_code": status,
        "response_time_ms": 5.0,
        "user_id": None,
        "timestamp": "",
        "unix_timestamp": now - age_seconds,
    }


@pytest.fixture(autouse=True)
def _clean_alerts():
    dm._alerts.clear()
    yield
    dm._alerts.clear()


@pytest.fixture()
def analyzer() -> BehavioralAnalyzer:
    return BehavioralAnalyzer()


def _find_mw(app):
    node = getattr(app, "middleware_stack", None)
    while node is not None:
        if isinstance(node, dm.DefenseMiddleware):
            return node
        node = getattr(node, "app", None)
    return None


# ─── B1: session identity ────────────────────────────────────


def test_extract_user_id_paths(analyzer):
    B = BehavioralAnalyzer
    valid = B.extract_user_id("Bearer " + create_access_token("u-1"))
    assert valid == "u-1"

    from datetime import timedelta

    expired = B.extract_user_id(
        "Bearer " + create_access_token("u-2", expires_delta=timedelta(seconds=-10))
    )
    assert expired == "u-2"  # genuine but lapsed: identity still known

    forged = create_access_token("u-victim").rsplit(".", 1)[0] + ".badbadbad"
    assert B.extract_user_id("Bearer " + forged) is None  # NO impersonation

    assert B.extract_user_id("Bearer garbage") is None
    assert B.extract_user_id("Basic abc") is None
    assert B.extract_user_id(None) is None
    assert B.extract_user_id("Bearer ") is None


def test_session_key_shape(analyzer):
    assert analyzer.session_key("1.2.3.4", None) == "ip:1.2.3.4"
    assert analyzer.session_key("1.2.3.4", "u-9") == "user:u-9"


async def test_user_traffic_merges_across_ips(analyzer):
    """B1: the SAME user from two different IPs keeps ONE profile;
    anonymous traffic stays IP-keyed."""
    await analyzer.record_activity(
        "10.0.0.1", "/a", "GET", 200, 5.0, user_id="u-1"
    )
    await analyzer.record_activity(
        "10.0.0.2", "/b", "GET", 200, 5.0, user_id="u-1"
    )
    await analyzer.record_activity("10.0.0.3", "/c", "GET", 200, 5.0)

    assert "user:u-1" in analyzer.session_profiles
    assert len(analyzer.session_profiles["user:u-1"]) == 2
    assert "ip:10.0.0.3" in analyzer.session_profiles
    # no stray raw-IP key for the authenticated traffic
    assert "ip:10.0.0.1" not in analyzer.session_profiles
    assert "ip:10.0.0.2" not in analyzer.session_profiles


async def test_ip_alias_risk_tracking(analyzer):
    """Risk is also visible under the raw-IP key for IP-based lookups."""
    for _ in range(45):
        await analyzer.record_activity("10.9.9.9", "/x", "GET", 200, 2.0)
    ip_key = analyzer.session_key("10.9.9.9", None)
    assert ip_key in analyzer.risk_scores
    assert analyzer.risk_scores[ip_key] > 0.0


async def test_authenticated_traffic_correlated_live(client):
    """End-to-end: a request carrying a user token is profiled under
    the USER identity, not the client IP."""
    # Warm-up: the middleware stack is built on the first ASGI call.
    await client.get("/health")
    mw = _find_mw(app)
    assert mw is not None
    mw.behavioral_analyzer.session_profiles.clear()
    mw.behavioral_analyzer.baselines.clear()

    token = create_access_token("live-user-42")
    r = await client.get(
        "/api/v1/public/stats", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    ba = mw.behavioral_analyzer
    assert "user:live-user-42" in ba.session_profiles

    r2 = await client.get("/api/v1/public/stats")
    anon_keys = [k for k in ba.session_profiles if k.startswith("ip:")]
    assert anon_keys, "anonymous traffic must be IP-keyed"


# ─── B2: time-decayed risk + z-score ─────────────────────────


def test_burst_is_flagged_calm_is_not(analyzer):
    now = time.time()
    # 60 fresh requests, 20 of them 404s, 25 unique endpoints, one /admin
    profile = []
    for i in range(60):
        ep = f"/api/v1/items/{i % 25}"
        status = 404 if i < 20 else 200
        profile.append(act(ep, status, age_seconds=i * 0.05, now=now))
    profile.append(act("/admin/dashboard", 200, age_seconds=0.0, now=now))
    score, reasons = analyzer._score_signals(
        profile, profile[-1], now, "ip:test-burst"
    )
    assert score > analyzer.ANOMALY_THRESHOLD
    assert any("request rate" in r for r in reasons)
    assert any("error rate" in r for r in reasons)
    assert any("enumeration" in r for r in reasons)

    # calm: 8 requests spread over 40s, all 200, 2 endpoints
    calm = [
        act(f"/api/v1/a{i % 2}", 200, age_seconds=i * 5.0, now=now)
        for i in range(8)
    ]
    calm_score, calm_reasons = analyzer._score_signals(
        calm, calm[-1], now, "ip:test-calm"
    )
    assert calm_score < analyzer.ANOMALY_THRESHOLD
    assert calm_reasons == []


def test_stale_activity_decays_out(analyzer):
    """Activity older than the 60s window must not contribute at all."""
    now = time.time()
    old = [
        act(f"/api/v1/items/{i}", 404, age_seconds=120 + i, now=now)
        for i in range(50)
    ]
    score, reasons = analyzer._score_signals(old, old[-1], now, "ip:test-stale")
    assert score == 0.0
    assert reasons == []


def test_zscore_fires_on_established_baseline(analyzer):
    """An established calm baseline + sudden burst -> deviation signal."""
    now = time.time()
    skey = "user:z-test"
    # 60 clean samples at ~1 req/30s -> mean ~1.5, tiny variance
    for i in range(60):
        analyzer._maybe_update_baseline(
            skey,
            [act("/api/v1/home", 200, age_seconds=i * 30.0, now=now - 3600 + i * 30)],
            act("/api/v1/home", 200, age_seconds=i * 30.0, now=now - 3600 + i * 30),
        )
    base = analyzer.baselines[skey]
    assert base["samples"] == 60

    # 80 fresh requests over 8s across 25 endpoints: rate (0.30) +
    # enumeration (0.125) + deviation (0.30) -> clearly over threshold
    burst = [act(f"/api/v1/items/{i % 25}", 200, age_seconds=i * 0.1, now=now)
             for i in range(80)]
    score, reasons = analyzer._score_signals(burst, burst[-1], now, skey)
    assert any("Behavioral deviation: z=" in r for r in reasons)
    assert score > analyzer.ANOMALY_THRESHOLD


def test_cold_start_has_no_zsignal(analyzer):
    """Fewer than BASELINE_MIN_SAMPLES -> deviation signal is absent
    (strangers are covered by heuristics, not z-scores)."""
    now = time.time()
    skey = "ip:cold"
    small = [act(f"/api/v1/items/{i % 30}", 200, age_seconds=i * 0.2, now=now)
             for i in range(35)]
    score, reasons = analyzer._score_signals(small, small[-1], now, skey)
    assert not any("Behavioral deviation" in r for r in reasons)


# ─── B4: baseline poisoning guard ────────────────────────────


def test_baseline_ignores_4xx_traffic(analyzer):
    """Failed-auth / validation / scan responses NEVER shape the
    baseline — the core anti-poisoning guarantee."""
    now = time.time()
    skey = "ip:poison"
    a1 = act("/api/v1/auth/login", 200, age_seconds=0.0, now=now)
    analyzer._maybe_update_baseline(skey, [a1], a1)
    samples_after_clean = analyzer.baselines[skey]["samples"]
    mean_after_clean = analyzer.baselines[skey]["mean"]

    # 20 failed logins (401) — must be invisible to the baseline
    for i in range(20):
        a = act("/api/v1/auth/login", 401, age_seconds=i * 0.1, now=now)
        analyzer._maybe_update_baseline(skey, [a], a)

    assert analyzer.baselines[skey]["samples"] == samples_after_clean
    assert analyzer.baselines[skey]["mean"] == pytest.approx(mean_after_clean)


def test_baseline_learning_rate_capped(analyzer):
    """EWMA alpha=0.1: one clean request moves the mean by AT MOST
    10% of the gap — a stealth attack shifts it far too slowly."""
    now = time.time()
    skey = "ip:cap"
    a1 = act("/api/v1/home", 200, age_seconds=0.0, now=now)
    analyzer._maybe_update_baseline(skey, [a1], a1)
    first_mean = analyzer.baselines[skey]["mean"]

    # a burst of clean requests (much higher instantaneous rate)
    fast = [act(f"/api/v1/x{i}", 200, age_seconds=i * 0.1, now=now + 1000)
            for i in range(10)]
    a = fast[-1]
    analyzer._maybe_update_baseline(skey, fast, a)
    new_mean = analyzer.baselines[skey]["mean"]

    # The baseline updates relative to the ACTIVITY's own timestamp.
    signals = analyzer._weighted_signals(fast, a["unix_timestamp"])
    expected = first_mean + analyzer.BASELINE_ALPHA * (
        signals["rate_weight"] - first_mean
    )
    assert new_mean == pytest.approx(expected)
    assert new_mean < signals["rate_weight"]  # did NOT jump to the new value


# ─── B3: explainable alerts ──────────────────────────────────


def test_alert_schema_fields_backward_compatible():
    from datetime import datetime, timezone

    old = SecurityAlertItem(
        id="a1",
        severity="high",
        title="t",
        description="d",
        source_ip="1.2.3.4",
        attack_type="x",
        blocked=True,
        created_at=datetime.now(timezone.utc),
    )
    assert old.reasons == []
    assert old.risk_score is None
    assert old.confidence is None
    assert old.session is None


def test_record_and_get_alerts():
    dm.record_security_alert(
        severity="high",
        title="T1",
        description="D1",
        source_ip="1.1.1.1",
        attack_type="behavioral_anomaly",
        risk_score=0.91,
        confidence=0.91,
        reasons=["High request rate: decayed weight 62.3 over 60s"],
        session="ip:1.1.1.1",
    )
    dm.record_security_alert(
        severity="low",
        title="T2",
        description="D2",
        source_ip="2.2.2.2",
        attack_type="protocol_violation",
        confidence=0.98,
        reasons=["HTTP method TRACE not in allowlist"],
    )
    alerts = dm.get_security_alerts(limit=10)
    assert len(alerts) == 2
    assert alerts[0]["title"] == "T2"  # newest first
    assert alerts[0]["reasons"] == ["HTTP method TRACE not in allowlist"]
    assert alerts[1]["risk_score"] == 0.91
    assert alerts[1]["session"] == "ip:1.1.1.1"


def test_alert_ring_cap():
    for i in range(dm.MAX_ALERTS + 10):
        dm.record_security_alert(
            severity="low",
            title=f"T{i}",
            description="d",
            source_ip="9.9.9.9",
            attack_type="test",
        )
    assert len(dm.get_security_alerts(limit=1000)) == dm.MAX_ALERTS


async def test_alerts_flow_through_service_live(client, db_session):
    """Live: a protocol rejection recorded by the middleware appears in
    the defense API's alert feed WITH its reasons and confidence."""
    r = await client.request("TRACE", "/api/v1/public/stats")
    assert r.status_code == 405

    service = DefenseService(db_session)
    resp = await service.get_alerts("admin-1")
    assert resp.total >= 1
    item = resp.items[0]
    assert item.attack_type == "protocol_violation"
    assert item.confidence == 0.98
    assert len(item.reasons) >= 1
    assert "TRACE" in item.reasons[0]

    dashboard = await service.get_dashboard("admin-1")
    assert len(dashboard.recent_alerts) >= 1
    assert dashboard.recent_alerts[0].attack_type == "protocol_violation"
