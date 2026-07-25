"""
Test Configuration — Shared fixtures for pytest.
"""

import asyncio  # noqa: I001
from collections.abc import AsyncGenerator
import uuid

import pytest  # type: ignore[import-not-found]
import pytest_asyncio  # type: ignore[import-not-found]
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine

from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app

# Use a test database
TEST_DATABASE_URL = settings.DATABASE_URL.replace("cerberus", "cerberus_test")

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Create and drop test database tables."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:  # noqa: UP043
    """Provide a test database session."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:  # noqa: UP043
    """Provide a test HTTP client."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


def generate_test_email() -> str:
    return f"test_{uuid.uuid4().hex[:8]}@cerberus-test.com"
