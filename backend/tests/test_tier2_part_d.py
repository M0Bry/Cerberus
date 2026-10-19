"""
Tier 2 — Part D tests: session lifecycle, per-user limits,
session drift, alert persistence.

D1: real logout (session revocation), refresh-token rotation with
    replay rejection, per-user session cap with oldest eviction.
D3: per-user (per-account) rate limits + strict refresh sub-budget.
D5: session-drift signal (new IP/24 or device for an established
    user) — risk-only, never blocking.
D2: defense-alert persistence into the durable audit_log table.

Isolation: the autouse conftest fixture calls reset_defense_state,
which clears the SessionRegistry and the analyzer pair store, and
RateLimitMiddleware (per-test fresh user buckets).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.core.session_registry import SessionRegistry, hash_ua
from app.db.models.user import User, UserRole, UserStatus


# ═══════════════════════════════════════════════════════════
# D1 — SessionRegistry unit tests
# ═══════════════════════════════════════════════════════════


def test_registry_register_active_revoke():
    SessionRegistry.reset_all()
    SessionRegistry.register("u1", "s1", "j1", ip="1.2.3.4")
    assert SessionRegistry.is_active("u1", "s1")
    assert SessionRegistry.active_count("u1") == 1
    assert SessionRegistry.revoke("u1", "s1") is True
    assert SessionRegistry.is_active("u1", "s1") is False
    assert SessionRegistry.revoke("u1", "s1") is False  # idempotent


def test_registry_cap_evicts_oldest():
    SessionRegistry.reset_all()
    old_max = settings.SESSION_MAX_ACTIVE
    settings.SESSION_MAX_ACTIVE = 3
    try:
        for i in range(3):
            assert SessionRegistry.register("u1", f"s{i}", f"j{i}") is None
        evicted = SessionRegistry.register("u1", "s3", "j3")
        assert evicted == "s0"  # the OLDEST session dies
        assert SessionRegistry.is_active("u1", "s0") is False
        assert SessionRegistry.is_active("u1", "s3") is True
        assert SessionRegistry.active_count("u1") == 3
    finally:
        settings.SESSION_MAX_ACTIVE = old_max


def test_registry_rotate_jti():
    SessionRegistry.reset_all()
    SessionRegistry.register("u1", "s1", "j1")
    assert SessionRegistry.get_jti("u1", "s1") == "j1"
    assert SessionRegistry.rotate_jti("u1", "s1", "j2") is True
    assert SessionRegistry.get_jti("u1", "s1") == "j2"
    # Rotating an unknown session fails (closed session).
    assert SessionRegistry.rotate_jti("u1", "nope", "j9") is False


def test_registry_revoke_all():
    SessionRegistry.reset_all()
    SessionRegistry.register("u1", "s1", "j1")
    SessionRegistry.register("u1", "s2", "j2")
    assert SessionRegistry.revoke_all("u1") == 2
    assert SessionRegistry.active_count("u1") == 0


def test_hash_ua_stable_and_bounded():
    h1 = hash_ua("Mozilla/5.0 (X11; Linux x86_64) Chrome/120")
    h2 = hash_ua("Mozilla/5.0 (X11; Linux x86_64) Chrome/120")
    assert h1 == h2
    assert len(h1) == 12
    assert hash_ua(None) is None
    assert hash_ua("") is None


# ═══════════════════════════════════════════════════════════
# D1 — live: session lifecycle
# ═══════════════════════════════════════════════════════════


def _verified_user(email: str) -> User:
    return User(
        id=str(uuid.uuid4()),
        full_name="Part D Test",
        email=email,
        company_name="PD",
        job_title="Eng",
        hashed_password=hash_password("Part#D1234"),
        status=UserStatus.VERIFIED,
        role=UserRole.USER,
    )


async def _login(client: AsyncClient, email: str) -> dict:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Part#D1234"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_login_issues_session_logout_revokes(
    client: AsyncClient, db_session
):
    email = f"sess_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    db_session.add(_verified_user(email))
    await db_session.flush()

    tok = await _login(client, email)
    access = tok["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    # Session works while active.
    resp = await client.get("/api/v1/engagements", headers=headers)
    assert resp.status_code == 200, resp.text

    # Logout revokes the session...
    resp = await client.post("/api/v1/auth/logout", headers=headers)
    assert resp.status_code == 200, resp.text
    # ...and the SAME access token now fails.
    resp = await client.get("/api/v1/engagements", headers=headers)
    assert resp.status_code == 401
    # ...and the session's refresh token is dead too.
    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tok["refresh_token"]}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rotation_and_replay(
    client: AsyncClient, db_session
):
    email = f"rot_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    db_session.add(_verified_user(email))
    await db_session.flush()

    tok = await _login(client, email)
    refresh1 = tok["refresh_token"]

    # First rotation: old refresh is consumed, new one issued.
    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh1}
    )
    assert resp.status_code == 200, resp.text
    refresh2 = resp.json()["refresh_token"]

    # REPLAY of the already-rotated token is rejected (theft signal).
    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh1}
    )
    assert resp.status_code == 401

    # The NEW token works.
    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh2}
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_session_cap_evicts_oldest_live(
    client: AsyncClient, db_session, monkeypatch
):
    """With a cap of 2, the 3rd login evicts the first session — its
    tokens die, the newest works."""
    monkeypatch.setattr(settings, "SESSION_MAX_ACTIVE", 2)
    email = f"cap_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    db_session.add(_verified_user(email))
    await db_session.flush()

    tok1 = await _login(client, email)
    tok2 = await _login(client, email)
    tok3 = await _login(client, email)

    # Oldest session was evicted → its access token fails.
    resp = await client.get(
        "/api/v1/engagements",
        headers={"Authorization": f"Bearer {tok1['access_token']}"},
    )
    assert resp.status_code == 401
    # Newest sessions are fine.
    for t in (tok2, tok3):
        resp = await client.get(
            "/api/v1/engagements",
            headers={"Authorization": f"Bearer {t['access_token']}"},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_legacy_token_without_sid_still_works(
    client: AsyncClient, db_session
):
    """Tokens minted without sid (pre-Part D / admin portal) are not
    gated by the registry — no breakage for existing sessions."""
    email = f"legacy_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    user = _verified_user(email)
    db_session.add(user)
    await db_session.flush()

    legacy = create_access_token(subject=user.id)  # no sid/jti
    resp = await client.get(
        "/api/v1/engagements",
        headers={"Authorization": f"Bearer {legacy}"},
    )
    assert resp.status_code == 200, resp.text


# ═══════════════════════════════════════════════════════════
# D3 — per-user rate limits
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_user_rate_limit_enforced(
    client: AsyncClient, db_session, monkeypatch
):
    """The per-USER bucket is separate from the IP bucket: 3/min cap
    → the 4th authenticated request is 429 (the IP never approaches
    its own budget in this test)."""
    monkeypatch.setattr(settings, "DEFENSE_USER_RATE_LIMIT", 3)
    email = f"uratel_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    db_session.add(_verified_user(email))
    await db_session.flush()

    tok = await _login(client, email)
    headers = {"Authorization": f"Bearer {tok['access_token']}"}

    for _ in range(3):
        resp = await client.get("/api/v1/engagements", headers=headers)
        assert resp.status_code == 200, resp.text
    resp = await client.get("/api/v1/engagements", headers=headers)
    assert resp.status_code == 429
    assert "retry-after" in {k.lower() for k in resp.headers.keys()}


@pytest.mark.asyncio
async def test_refresh_sub_budget_enforced(
    client: AsyncClient, db_session, monkeypatch
):
    """The refresh endpoint has a strict per-user sub-budget: 2/min →
    the 3rd refresh is 429 even though the general user budget (120)
    is far from exhausted."""
    monkeypatch.setattr(settings, "DEFENSE_REFRESH_RATE_LIMIT", 2)
    email = f"rsub_{uuid.uuid4().hex[:8]}@cerberus-test.com"
    db_session.add(_verified_user(email))
    await db_session.flush()

    tok = await _login(client, email)
    current = tok["refresh_token"]
    for _ in range(2):
        resp = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": current}
        )
        assert resp.status_code == 200, resp.text
        current = resp.json()["refresh_token"]
    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": current}
    )
    assert resp.status_code == 429


# ═══════════════════════════════════════════════════════════
# D5 — session-drift signal
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_session_drift_detected_for_new_network():
    from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer

    a = BehavioralAnalyzer()
    uid = str(uuid.uuid4())

    # Establish a dominant pair: same /24 + same UA, 3 samples.
    for _ in range(3):
        await a.record_activity(
            client_ip="10.0.0.5",
            endpoint="/api/v1/engagements",
            method="GET",
            status_code=200,
            response_time_ms=10.0,
            user_id=uid,
            user_agent="Mozilla/5.0 (Windows) Chrome/120",
        )

    # Same user from a DIFFERENT /24 (same device) → drift on the
    # next observation.
    result = await a.record_activity(
        client_ip="172.31.7.9",
        endpoint="/api/v1/engagements",
        method="GET",
        status_code=200,
        response_time_ms=10.0,
        user_id=uid,
        user_agent="Mozilla/5.0 (Windows) Chrome/120",
    )
    drift_reasons = [r for r in result["reasons"] if "Session drift" in r]
    assert drift_reasons, f"expected a drift reason, got {result['reasons']}"
    assert "new network" in drift_reasons[0]


@pytest.mark.asyncio
async def test_session_drift_new_device_same_network():
    from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer

    a = BehavioralAnalyzer()
    uid = str(uuid.uuid4())

    for _ in range(3):
        await a.record_activity(
            client_ip="10.0.0.5",
            endpoint="/api/v1/engagements",
            method="GET",
            status_code=200,
            response_time_ms=10.0,
            user_id=uid,
            user_agent="Mozilla/5.0 (Windows) Chrome/120",
        )

    # Same /24, DIFFERENT device → drift (stolen token on new laptop).
    result = await a.record_activity(
        client_ip="10.0.0.9",
        endpoint="/api/v1/engagements",
        method="GET",
        status_code=200,
        response_time_ms=10.0,
        user_id=uid,
        user_agent="Mozilla/5.0 (iPhone) Safari/17",
    )
    drift_reasons = [r for r in result["reasons"] if "Session drift" in r]
    assert drift_reasons
    assert "device" in drift_reasons[0]


@pytest.mark.asyncio
async def test_session_drift_cold_start_does_not_fire():
    """Fewer than DRIFT_MIN_SAMPLES observations → no drift (mobile
    networks flap on first use)."""
    from app.ai_engine.defense.tier2_behavioral import BehavioralAnalyzer

    a = BehavioralAnalyzer()
    uid = str(uuid.uuid4())

    await a.record_activity(
        client_ip="10.0.0.5",
        endpoint="/x",
        method="GET",
        status_code=200,
        response_time_ms=1.0,
        user_id=uid,
        user_agent="UA-A",
    )
    result = await a.record_activity(
        client_ip="172.31.7.9",
        endpoint="/x",
        method="GET",
        status_code=200,
        response_time_ms=1.0,
        user_id=uid,
        user_agent="UA-B",
    )
    assert not [r for r in result["reasons"] if "Session drift" in r]


# ═══════════════════════════════════════════════════════════
# D2 — alert persistence
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_alert_persistence_writes_audit_rows(db_session):
    from app.core.alert_persistence import persist_new_alerts
    from app.api.v1.middleware.defense_middleware import record_security_alert
    from sqlalchemy import func, select

    from app.db.models.audit_log import AuditAction, AuditLog

    state = {"last_seq": 0}

    # One low alert (must NOT persist) + one high alert (must).
    record_security_alert(
        severity="low",
        title="Shadow-ish",
        description="low severity test alert",
        source_ip="10.1.1.1",
        attack_type="prompt_injection",
        blocked=False,
    )
    record_security_alert(
        severity="high",
        title="Hard block",
        description="high severity test alert",
        source_ip="10.2.2.2",
        attack_type="cost_abuse",
        blocked=True,
        risk_score=0.8,
        confidence=0.9,
        reasons=["budget exhausted"],
    )

    written = await persist_new_alerts(session=db_session, _state=state)
    assert written == 1

    result = await db_session.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.action == AuditAction.SECURITY_ALERT,
            AuditLog.description.like("[defense:%"),
        )
    )
    count = result.scalar_one()
    assert count == 1

    # Idempotent: a second flush with the same cursor writes nothing.
    written2 = await persist_new_alerts(session=db_session, _state=state)
    assert written2 == 0
