"""
Authentication API Tests.
"""

import pytest  # type: ignore[import-not-found]
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    """Test successful user registration."""
    response = await client.post("/api/v1/auth/register", json={
        "full_name": "Test User",
        "company_name": "Test Corp",
        "job_title": "Security Engineer",
        "email": "test@cerberus-test.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert "user_id" in data
    assert "email_masked" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    """Test registration with duplicate email."""
    payload = {
        "full_name": "Test User",
        "company_name": "Test Corp",
        "job_title": "Engineer",
        "email": "duplicate@cerberus-test.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
    }
    await client.post("/api/v1/auth/register", json=payload)
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_password_mismatch(client: AsyncClient):
    """Test registration with mismatched passwords."""
    response = await client.post("/api/v1/auth/register", json={
        "full_name": "Test User",
        "company_name": "Test Corp",
        "job_title": "Engineer",
        "email": "mismatch@cerberus-test.com",
        "password": "SecurePass123!",
        "confirm_password": "DifferentPass456!",
    })
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_before_verification(client: AsyncClient):
    """Test that login is blocked before email verification."""
    await client.post("/api/v1/auth/register", json={
        "full_name": "Unverified User",
        "company_name": "Test Corp",
        "job_title": "Engineer",
        "email": "unverified@cerberus-test.com",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
    })
    response = await client.post("/api/v1/auth/login", json={
        "email": "unverified@cerberus-test.com",
        "password": "SecurePass123!",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Test login with invalid credentials."""
    response = await client.post("/api/v1/auth/login", json={
        "email": "nonexistent@cerberus-test.com",
        "password": "WrongPass123!",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
