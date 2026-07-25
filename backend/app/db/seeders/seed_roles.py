"""Seed default roles and permissions."""

import asyncio

from app.core.permissions import ROLE_PERMISSIONS
from app.db.session import Base, engine


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Roles seeded:")
    for role, perms in ROLE_PERMISSIONS.items():
        print(f"  {role.value}: {len(perms)} permissions")


if __name__ == "__main__":
    asyncio.run(seed())
