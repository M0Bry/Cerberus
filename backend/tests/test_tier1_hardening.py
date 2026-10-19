"""Tier-1 hardening (Part A) — regression + behavior tests.

Covers:
  A1  Trusted client-IP resolution (X-Forwarded-For anti-spoofing)
  A2  HTTP method allowlist (TRACE / custom verbs rejected)
  A3  Body-size caps + Content-Length policy
  A4  Login timing equalization (bcrypt always runs)
  A5  Anti-enumeration on verify-otp / resend-otp
"""

import uuid

import pytest
from starlette.requests import Request

from app.core import ip_resolver
from app.core.config import settings
from app.core.exceptions import AuthenticationError, OTPError
from app.core.security import hash_password
from app.api.v1.middleware.defense_middleware import DefenseMiddleware
from app.db.models.user import User, UserRole, UserStatus
from app.schemas.auth import LoginRequest, ResendOTPRequest, VerifyOTPRequest
from app.services.auth_service import AuthService


def make_request(
    method: str = "POST", path: str = "/api/v1/auth/login", headers=None
) -> Request:
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


@pytest.fixture(autouse=True)
def _reset_resolver():
    yield
    settings.TRUSTED_PROXY_CIDRS = ""
    ip_resolver._trusted_networks.cache_clear()


def _make_user(
    email: str, status: UserStatus = UserStatus.PENDING_VERIFICATION
) -> User:
    return User(
        id=str(uuid.uuid4()),
        full_name="Test User",
        email=email,
        company_name="Test Co",
        job_title="Engineer",
        hashed_password=hash_password("Test#Pass123"),
        status=status,
        role=UserRole.USER,
    )


# ─── A1: trusted IP resolution ───────────────────────────────


def test_xff_ignored_from_untrusted_peer():
    """The default (no trusted proxies) is spoof-proof: XFF is noise."""
    settings.TRUSTED_PROXY_CIDRS = ""
    ip_resolver._trusted_networks.cache_clear()
    got = ip_resolver.resolve_client_ip(
        "203.0.113.7", {"x-forwarded-for": "1.2.3.4, 5.6.7.8"}
    )
    assert got == "203.0.113.7"


def test_xff_respected_from_trusted_proxy_rightmost_untrusted():
    settings.TRUSTED_PROXY_CIDRS = "10.0.0.0/8"
    ip_resolver._trusted_networks.cache_clear()
    got = ip_resolver.resolve_client_ip(
        "10.1.2.3", {"x-forwarded-for": "6.6.6.6, 10.9.9.9, 7.7.7.7"}
    )
    # right-to-left: 7.7.7.7 is the first untrusted hop.
    assert got == "7.7.7.7"


def test_xff_malformed_hops_are_dropped_not_fatal():
    settings.TRUSTED_PROXY_CIDRS = "10.0.0.0/8"
    ip_resolver._trusted_networks.cache_clear()
    got = ip_resolver.resolve_client_ip(
        "10.1.2.3", {"x-forwarded-for": "evil, 6.6.6.6, not-an-ip, 3.3.3.3"}
    )
    assert got == "3.3.3.3"


def test_all_trusted_chain_falls_back_to_leftmost():
    settings.TRUSTED_PROXY_CIDRS = "10.0.0.0/8"
    ip_resolver._trusted_networks.cache_clear()
    got = ip_resolver.resolve_client_ip(
        "10.1.2.3", {"x-forwarded-for": "10.9.9.9, 10.8.8.8"}
    )
    assert got == "10.9.9.9"


def test_trusted_proxy_without_xff_uses_peer():
    settings.TRUSTED_PROXY_CIDRS = "10.0.0.0/8"
    ip_resolver._trusted_networks.cache_clear()
    got = ip_resolver.resolve_client_ip("10.1.2.3", {})
    assert got == "10.1.2.3"


# ─── A2 + A3: protocol hardening (unit-level) ────────────────


def test_method_allowlist_blocks_trace():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("TRACE", "/api/v1/public/stats")
    )
    assert resp is not None
    assert resp.status_code == 405
    assert "TRACE" not in resp.headers["Allow"]
    assert "GET" in resp.headers["Allow"]


def test_method_allowlist_blocks_custom_verb():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("FOO", "/api/v1/public/stats")
    )
    assert resp is not None
    assert resp.status_code == 405


def test_allowed_methods_pass():
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        resp = DefenseMiddleware._check_protocol_hardening(
            make_request(method, "/api/v1/engagements", {"content-length": "10"})
        )
        assert resp is None, f"{method} must not be rejected"


def test_expect_100_continue_rejected():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("POST", "/api/v1/public/stats", {"Expect": "100-continue"})
    )
    assert resp is not None
    assert resp.status_code == 411


def test_auth_body_over_cap_rejected_413():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request(
            "POST",
            "/api/v1/auth/login",
            {"content-length": str(settings.DEFENSE_MAX_BODY_AUTH_BYTES + 1)},
        )
    )
    assert resp is not None
    assert resp.status_code == 413


def test_auth_body_at_cap_allowed():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request(
            "POST",
            "/api/v1/auth/login",
            {"content-length": str(settings.DEFENSE_MAX_BODY_AUTH_BYTES)},
        )
    )
    assert resp is None


def test_auth_missing_content_length_rejected_411():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("POST", "/api/v1/auth/login")
    )
    assert resp is not None
    assert resp.status_code == 411


def test_general_body_over_cap_rejected_413():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request(
            "POST",
            "/api/v1/public/contact",
            {"content-length": str(settings.DEFENSE_MAX_BODY_BYTES + 1)},
        )
    )
    assert resp is not None
    assert resp.status_code == 413


def test_upload_path_uses_document_cap_and_allows_missing_cl():
    cap = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    assert (
        DefenseMiddleware._check_protocol_hardening(
            make_request(
                "POST",
                "/api/v1/documents/abc/upload",
                {"content-length": str(cap + 1)},
            )
        ).status_code
        == 413
    )
    assert (
        DefenseMiddleware._check_protocol_hardening(
            make_request(
                "POST",
                "/api/v1/documents/abc/upload",
                {"content-length": str(cap)},
            )
        )
        is None
    )
    # Non-browser clients may stream uploads chunked (no CL).
    assert (
        DefenseMiddleware._check_protocol_hardening(
            make_request("POST", "/api/v1/documents/abc/upload")
        )
        is None
    )


def test_invalid_content_length_rejected_400():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("POST", "/api/v1/public/contact", {"content-length": "abc"})
    )
    assert resp is not None
    assert resp.status_code == 400


def test_get_requests_skip_body_checks():
    resp = DefenseMiddleware._check_protocol_hardening(
        make_request("GET", "/api/v1/engagements", {"content-length": "999999999"})
    )
    assert resp is None


# ─── A2 + A3: live through the middleware stack ──────────────


async def test_trace_rejected_live(client):
    r = await client.request("TRACE", "/api/v1/public/stats")
    assert r.status_code == 405


async def test_oversized_login_rejected_live(client):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@cerberus-test.com", "password": "A" * 9000},
    )
    assert r.status_code == 413


# ─── A4: login timing equalization ───────────────────────────


async def test_login_unknown_email_still_runs_bcrypt(db_session, monkeypatch):
    """Unknown email must perform a bcrypt check (timing oracle closed)."""
    from app.services import auth_service as auth_mod

    calls = []
    original = auth_mod.verify_password

    def spy(plain, hashed):
        calls.append((plain, hashed))
        return original(plain, hashed)

    monkeypatch.setattr(auth_mod, "verify_password", spy)
    service = AuthService(db_session)
    with pytest.raises(AuthenticationError):
        await service.login(
            make_request(),
            LoginRequest(email="ghost@nowhere-domain.com", password="Wrong#Pass1"),
        )
    assert len(calls) == 1, "dummy bcrypt verification did not run"


async def test_login_known_user_wrong_password_same_cost(db_session, monkeypatch):
    from app.services import auth_service as auth_mod

    db_session.add(_make_user("real@nowhere-domain.com", UserStatus.VERIFIED))
    await db_session.flush()

    calls = []
    original = auth_mod.verify_password

    def spy(plain, hashed):
        calls.append((plain, hashed))
        return original(plain, hashed)

    monkeypatch.setattr(auth_mod, "verify_password", spy)
    service = AuthService(db_session)
    with pytest.raises(AuthenticationError):
        await service.login(
            make_request(),
            LoginRequest(email="real@nowhere-domain.com", password="Wrong#Pass1"),
        )
    assert len(calls) == 1


# ─── A5: anti-enumeration ────────────────────────────────────


async def test_verify_otp_unknown_email_generic_error(db_session):
    service = AuthService(db_session)
    with pytest.raises(OTPError) as ei:
        await service.verify_otp(
            make_request("POST", "/api/v1/auth/verify-otp"),
            VerifyOTPRequest(email="ghost@nowhere-domain.com", otp="123456"),
        )
    # Must be the SAME message the wrong-code path produces.
    assert ei.value.detail == "Invalid verification code."
    assert ei.value.status_code == 400


async def test_verify_otp_verified_user_same_generic_error(db_session):
    """The 'already verified' fast path used to be a 200 oracle."""
    db_session.add(_make_user("verified@nowhere-domain.com", UserStatus.VERIFIED))
    await db_session.flush()
    service = AuthService(db_session)
    with pytest.raises(OTPError) as ei:
        await service.verify_otp(
            make_request("POST", "/api/v1/auth/verify-otp"),
            VerifyOTPRequest(email="verified@nowhere-domain.com", otp="123456"),
        )
    assert ei.value.detail == "Invalid verification code."
    assert ei.value.status_code == 400


async def test_resend_otp_unknown_email_uniform_shape(db_session):
    service = AuthService(db_session)
    resp = await service.resend_otp(
        make_request("POST", "/api/v1/auth/resend-otp"),
        ResendOTPRequest(email="ghost@nowhere-domain.com"),
    )
    assert resp.success is True
    assert resp.cooldown_seconds == settings.OTP_RESEND_COOLDOWN_SECONDS
    assert resp.message == "A new verification code has been sent."


async def test_resend_otp_verified_user_uniform_shape(db_session):
    db_session.add(_make_user("verified@nowhere-domain.com", UserStatus.VERIFIED))
    await db_session.flush()
    service = AuthService(db_session)
    resp = await service.resend_otp(
        make_request("POST", "/api/v1/auth/resend-otp"),
        ResendOTPRequest(email="verified@nowhere-domain.com"),
    )
    assert resp.cooldown_seconds == settings.OTP_RESEND_COOLDOWN_SECONDS
    assert resp.message == "A new verification code has been sent."
