"""Regression tests for the RateLimitMiddleware bucket separation.

Bug found in full SQA sweep (2026-10-19): the middleware kept ONE bucket
per client IP for every path, while the per-path LIMIT still varied
(login = 5/min, general = 60/min). Consequence: any IP that made ≥5
requests of ANY kind within a minute (a user just browsing the landing
page) received 429 on /auth/login — and 60 general requests per minute
were impossible for a single IP doing mixed traffic.

The fix keys the buckets per surface: "<ip>:login" vs "<ip>:general".
"""

from httpx import AsyncClient

from app.core.config import settings


async def test_general_traffic_does_not_poison_login_bucket(client: AsyncClient):
    """≥5 non-login requests from one IP must not block a subsequent login."""
    # Fire more than RATE_LIMIT_LOGIN_PER_MINUTE general requests.
    for _ in range(settings.RATE_LIMIT_LOGIN_PER_MINUTE + 2):
        r = await client.get("/api/v1/public/stats")
        assert r.status_code == 200, "general traffic should pass"

    # A login attempt right after (bad password on purpose) must be a
    # normal auth failure — NOT a 429 from the login limiter.
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@cerberus-test.com", "password": "WrongPass123"},
    )
    assert r.status_code != 429, (
        f"login bucket was poisoned by general traffic (got 429): {r.text}"
    )


async def test_login_bucket_is_enforced_separately(client: AsyncClient):
    """The login surface still enforces its 5/min-per-IP ceiling.

    Note (3-tier defense integration): the abuse detector's brute-force
    rule fires on the Nth failed login (403 'abusive behavior') BEFORE
    a 6th request ever reaches the rate limiter's 429, so the last
    attempt may be rejected by either layer. What must never happen is
    the 6th attempt succeeding (200/401)."""
    last = None
    for i in range(settings.RATE_LIMIT_LOGIN_PER_MINUTE + 1):
        last = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@cerberus-test.com", "password": f"Wrong{i}12345"},
        )
        if i < settings.RATE_LIMIT_LOGIN_PER_MINUTE:
            assert last.status_code != 429, f"attempt {i + 1} should be allowed"
        else:
            assert last.status_code in (403, 429), (
                f"attempt {i + 1} must be rejected (403 abuse / 429 rate limit), "
                f"got {last.status_code}"
            )


async def test_engagements_list_accepts_fe_page_sizes(client: AsyncClient):
    """Assessments/Reports pages request page_size=200 — the API must
    accept it (SQA FE sweep found a 422 contract mismatch)."""
    r = await client.get("/api/v1/engagements?page=1&page_size=200")
    # 401 without a token, but never 422 (the validation cap is the bug).
    assert r.status_code in (200, 401), f"page_size=200 rejected: {r.status_code}"
