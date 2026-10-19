"""
Cerberus AI — FastAPI Application Entry Point.

This module initializes the FastAPI application, registers all middleware,
exception handlers, and API routers. It follows a modular architecture
that allows new features to be added without modifying core logic.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Runs startup and shutdown logic for the FastAPI application.
    """
    # ─── Startup ──────────────────────────────────────────────
    from app.db.session import init_db
    await init_db()

    # Background: keep the DB truthful about expired free trials
    # (records SUSPENDED accounts every 30 minutes).
    from app.services.trial_sweep import trial_sweep_loop
    sweep_task = asyncio.create_task(trial_sweep_loop())

    # Tier 2 Part D: mirror medium/high defense alerts into the
    # durable audit_log so the defense record survives restarts.
    # Disabled under pytest: in the test process the app's session
    # factory targets the configured DB, which must not receive
    # defense-alert rows from the suite.
    import os

    persist_task = None
    _under_pytest = "PYTEST_CURRENT_TEST" in os.environ
    if settings.ALERT_PERSISTENCE_ENABLED and not _under_pytest:
        from app.core.alert_persistence import alert_persistence_loop

        persist_task = asyncio.create_task(alert_persistence_loop())

    yield
    # ─── Shutdown ─────────────────────────────────────────────
    sweep_task.cancel()
    if persist_task is not None:
        persist_task.cancel()
    await engine.dispose()


def create_application() -> FastAPI:
    """
    Factory function that creates and configures the FastAPI application.

    Returns:
        FastAPI: The fully configured application instance.
    """
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Cerberus AI — Intelligent Cybersecurity Platform. "
            "Automated penetration testing powered by AI."
        ),
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # ─── CORS Middleware ──────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ─── Custom Middleware ────────────────────────────────────
    from app.api.v1.middleware.defense_middleware import DefenseMiddleware
    from app.api.v1.middleware.rate_limiter import RateLimitMiddleware
    from app.api.v1.middleware.request_logging import RequestLoggingMiddleware

    application.add_middleware(RequestLoggingMiddleware)
    application.add_middleware(RateLimitMiddleware)
    application.add_middleware(DefenseMiddleware)  # Three-tier defense

    # ─── Exception Handlers ───────────────────────────────────
    register_exception_handlers(application)

    # ─── API Routers ──────────────────────────────────────────
    application.include_router(api_v1_router, prefix="/api/v1")

    # ─── Health Check ─────────────────────────────────────────
    @application.get("/health", tags=["System"])
    async def health_check():
        return {"status": "healthy", "version": settings.APP_VERSION}

    return application


app = create_application()
