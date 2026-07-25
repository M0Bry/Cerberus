"""Seed default admin account."""

import asyncio
import uuid
from datetime import datetime, timezone

from app.core.security import hash_password
from app.db.models.user import User, UserRole, UserStatus
from app.db.session import Base, async_session_factory, engine


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        admin = User(
            id=str(uuid.uuid4()),
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
        print(f"✅ Admin seeded: admin@cerberus-ai.com (ID: {admin.id})")
        print("⚠️  Change default password immediately!")


if __name__ == "__main__":
    asyncio.run(seed())
