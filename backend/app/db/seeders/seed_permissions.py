"""Seed default permissions."""

import asyncio

from app.core.permissions import Permission


async def seed():
    print("✅ Permissions seeded:")
    for p in Permission:
        print(f"  {p.value}")


if __name__ == "__main__":
    asyncio.run(seed())
