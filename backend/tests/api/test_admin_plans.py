"""Admin plan-management surface (GET/PUT /api/v1/admin/plans).

Added with the SQA full-sweep fix: plans ship with stripe_price_id =
NULL (the real IDs come from the operator's private Stripe account),
and checkout is 503 for unlinked plans. This is the only surface that
may read or write the Stripe link fields — the public /payments/plans
payload must never leak them.
"""

import uuid

import pytest_asyncio  # noqa: F401
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.main import app
from app.core.security import hash_password
from app.db.models.plan import Plan
from app.db.models.user import User, UserRole, UserStatus


def _user(role: UserRole) -> User:
    return User(
        id=str(uuid.uuid4()),
        full_name="Test " + role.value,
        email=f"{role.value}_{uuid.uuid4().hex[:8]}@cerberus-test.com",
        company_name="T",
        job_title="T",
        hashed_password=hash_password("Password123!"),
        status=UserStatus.VERIFIED,
        role=role,
    )


async def _seed_plans(db: AsyncSession) -> None:
    db.add_all(
        [
            Plan(
                id="plan-t1",
                name="T1",
                description=None,
                price_cents=100,
                currency="usd",
                interval="MONTH",
                is_active=True,
                stripe_price_id=None,
            ),
            Plan(
                id="plan-t2",
                name="T2",
                description=None,
                price_cents=200,
                currency="usd",
                interval="MONTH",
                is_active=False,
                stripe_price_id="price_existing",
            ),
        ]
    )
    await db.commit()


async def test_admin_can_list_and_update_plans(client: AsyncClient, db_session):
    await _seed_plans(db_session)
    admin = _user(UserRole.ADMIN)
    db_session.add(admin)
    await db_session.commit()

    async def override_admin():
        return admin

    app.dependency_overrides[get_current_user] = override_admin
    try:
        r = await client.get("/api/v1/admin/plans")
        assert r.status_code == 200
        plans = r.json()
        assert {p["id"] for p in plans} == {"plan-t1", "plan-t2"}
        by_id = {p["id"]: p for p in plans}
        assert by_id["plan-t2"]["stripe_price_id"] == "price_existing"
        assert by_id["plan-t1"]["is_active"] is True

        r = await client.put(
            "/api/v1/admin/plans/plan-t1",
            json={"stripe_price_id": "price_new_123", "price_cents": 150},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["stripe_price_id"] == "price_new_123"
        assert body["price_cents"] == 150
        # untouched field survives
        assert body["name"] == "T1"

        r = await client.put("/api/v1/admin/plans/plan-nope", json={"name": "X"})
        assert r.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)


async def test_non_admin_cannot_touch_plans(client: AsyncClient, db_session):
    await _seed_plans(db_session)
    normal = _user(UserRole.USER)
    db_session.add(normal)
    await db_session.commit()

    async def override_user():
        return normal

    app.dependency_overrides[get_current_user] = override_user
    try:
        r = await client.get("/api/v1/admin/plans")
        assert r.status_code == 403
        r = await client.put("/api/v1/admin/plans/plan-t1", json={"name": "X"})
        assert r.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


async def test_anonymous_cannot_list_plans(client: AsyncClient, db_session):
    r = await client.get("/api/v1/admin/plans")
    assert r.status_code == 401


async def test_public_plans_never_leak_stripe_fields(client: AsyncClient, db_session):
    await _seed_plans(db_session)
    r = await client.get("/api/v1/payments/plans")
    assert r.status_code == 200
    for plan in r.json():
        assert "stripe_price_id" not in plan
        assert "is_active" not in plan
