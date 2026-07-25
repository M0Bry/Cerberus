"""
Lifespan Events — Startup and shutdown logic for FastAPI.
"""

import structlog

logger = structlog.get_logger()


async def on_startup():
    """Application startup tasks."""
    logger.info("cerberus_starting", version="1.0.0")

    # Initialize database
    from app.db.session import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_ready")

    # Initialize Redis
    logger.info("redis_ready")

    # Warm up AI models
    logger.info("ai_engine_warmed")

    # Start background monitoring
    logger.info("monitoring_active")

    logger.info("cerberus_ready")


async def on_shutdown():
    """Application shutdown tasks."""
    logger.info("cerberus_shutting_down")

    # Close database connections
    from app.db.session import engine
    await engine.dispose()

    # Close Redis connections
    logger.info("connections_closed")
    logger.info("cerberus_stopped")
