"""
Application Configuration using Pydantic Settings.

All configuration is loaded from environment variables with sensible defaults.
This follows the Twelve-Factor App methodology for configuration management.
"""

import json

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Main application settings loaded from environment variables."""

    # ─── Application ──────────────────────────────────────────
    APP_NAME: str = "Cerberus AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # ─── Server ───────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4

    # ─── Database ─────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cerberus:cerberus_secret@localhost:5432/cerberus"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # ─── Redis ────────────────────────────────────────────────
    REDIS_URL: str = "redis://:cerberus_redis@localhost:6379/0"
    REDIS_PASSWORD: str = "cerberus_redis"

    # ─── Security ─────────────────────────────────────────────
    SECRET_KEY: str = ""  # REQUIRED — must be set via environment variable
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    OTP_EXPIRE_MINUTES: int = 5
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60

    # ─── CORS ─────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v

    # ─── Email (SMTP) ─────────────────────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_NAME: str = "Cerberus AI"
    SMTP_FROM_EMAIL: str = ""

    # ─── AI / OpenAI ──────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4-turbo"
    OPENAI_MAX_TOKENS: int = 4096

    # ─── Celery ───────────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://:cerberus_redis@localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://:cerberus_redis@localhost:6379/2"

    # ─── File Uploads ─────────────────────────────────────────
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_UPLOAD_EXTENSIONS: list[str] = [
        ".pdf", ".docx", ".xlsx", ".txt", ".csv", ".json", ".xml", ".zip"
    ]

    @field_validator("ALLOWED_UPLOAD_EXTENSIONS", mode="before")
    @classmethod
    def parse_upload_extensions(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v

    # ─── Rate Limiting ────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 5

    # ─── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()

# Validate critical security settings at import time
if not settings.SECRET_KEY or settings.SECRET_KEY == "change-me-to-a-random-64-char-string":
    import warnings
    warnings.warn(
        "SECRET_KEY is not set! Set it in your .env file. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"",
        stacklevel=2,
    )
