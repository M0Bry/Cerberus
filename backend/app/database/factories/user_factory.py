"""User Factory — Generate test user data."""

import uuid
from datetime import datetime, timezone

from app.core.security import hash_password


def create_user_data(**overrides) -> dict:
    """Generate user registration data."""
    data = {
        "id": str(uuid.uuid4()),
        "full_name": "Test User",
        "email": f"test_{uuid.uuid4().hex[:8]}@cerberus-test.com",
        "company_name": "Test Corp",
        "job_title": "Security Engineer",
        "hashed_password": hash_password("TestPass123!"),
        "status": "verified",
        "role": "user",
        "created_at": datetime.now(timezone.utc),  # noqa: UP017
    }
    data.update(overrides)
    return data


def create_admin_data(**overrides) -> dict:
    """Generate admin user data."""
    return create_user_data(
        full_name="Admin User",
        email="admin@cerberus-test.com",
        role="admin",
        **overrides,
    )
