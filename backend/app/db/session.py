"""
Database Session Management — Async SQLAlchemy Engine & Sessions.

Provides the async engine, session factory, and dependency injection
for FastAPI route handlers.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# ─── Async Engine ─────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    echo=settings.DEBUG,
    future=True,
)

# ─── Session Factory ─────────────────────────────────────────
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ─── Base Model ──────────────────────────────────────────────
class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy models."""
    pass


# ─── Dependency: get_db ──────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:  # noqa: UP043
    """
    FastAPI dependency that yields an async database session.
    Automatically commits on success and rolls back on exception.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Database Initialization ─────────────────────────────────
async def init_db() -> None:
    """
    Database initialization — DEPRECATED.

    In production, use Alembic migrations: `alembic upgrade head`
    This function only creates tables in development mode when explicitly needed.
    """
    if settings.DEBUG:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
