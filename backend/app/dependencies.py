"""
Common Dependencies — DB session, Redis, current user injection.
"""

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:  # noqa: UP043
    """FastAPI dependency: yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


_redis_client = None


async def get_redis() -> aioredis.Redis:
    """FastAPI dependency: returns a Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client
