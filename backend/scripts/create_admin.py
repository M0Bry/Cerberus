"""
Script: Create an admin user for initial platform setup.

Usage: python -m scripts.create_admin
"""

import asyncio
import uuid
from datetime import datetime, timezone

from app.core.security import hash_password  # type: ignore[import-not-found]
from app.db.models.user import User, UserRole, UserStatus  # type: ignore[import-not-found]
from app.db.session import Base, async_session_factory, engine  # type: ignore[import-not-found]


async def create_admin() -> None:
    """Create the initial admin user."""

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        admin_id = str(uuid.uuid4())
        admin = User(
            id=admin_id,
            full_name="System Administrator",
            email="admin@cerberus-ai.com",
            company_name="Cerberus AI",
            job_title="Platform Administrator",
            hashed_password=hash_password("Admin@Cerberus2026!"),
            status=UserStatus.VERIFIED,
            role=UserRole.SUPER_ADMIN,
            verified_at=datetime.now(timezone.utc),  # noqa: UP017
        )
        db.add(admin)
        await db.commit()

        print("Admin user created successfully!")
        print("   Email: admin@cerberus-ai.com")
        print(f"   ID: {admin_id}")
        print("   Change the default password immediately!")


if __name__ == "__main__":
    asyncio.run(create_admin())
