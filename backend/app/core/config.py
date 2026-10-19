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
    OTP_EXPIRE_SECONDS: int = 90  # 90s code — matches the 01:30 UI countdown
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    # Free trial: every new account gets full access for this many days from
    # registration. After expiry the account is recorded SUSPENDED in the DB
    # until a subscription becomes active (see app/services/access_service.py).
    TRIAL_DAYS: int = 7

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
    # Explicit TLS control: True = STARTTLS on 587-style ports;
    # port 465 automatically uses implicit TLS regardless.
    SMTP_USE_TLS: bool = True

    # ─── Email provider routing ───────────────────────────────
    # auto     → SMTP when configured, console otherwise (dev-friendly)
    # smtp     → SMTP (falls back to console with a loud warning if
    #            credentials are missing, so the flow never silently dies)
    # sendgrid → SendGrid API
    # console  → always print to the backend console (local development)
    EMAIL_PROVIDER: str = "auto"
    SENDGRID_API_KEY: str = ""
    SENDGRID_API_URL: str = "https://api.sendgrid.com"

    # ─── Payments (Stripe) ────────────────────────────────────
    # All merchant keys live BACKEND-ONLY (.env). Card data never touches
    # this server: checkout runs on Stripe's hosted page and we receive
    # only signed webhook events.
    STRIPE_SECRET_KEY: str = ""        # sk_test_... / sk_live_...
    STRIPE_PUBLISHABLE_KEY: str = ""   # pk_... (frontend-safe, unused with hosted checkout)
    STRIPE_WEBHOOK_SECRET: str = ""    # whsec_... (from the Stripe dashboard)
    STRIPE_MODE: str = "test"          # test | live
    # Base URL is overridable so the full flow can be verified against a
    # local mock in development (zero code change when going live).
    STRIPE_BASE_URL: str = "https://api.stripe.com"
    # Where the buyer lands after a completed/canceled checkout.
    FRONTEND_BASE_URL: str = "http://localhost:3000"

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

    # ─── Defense / Tier 1 (Gateway Protection) ────────────────
    DEFENSE_ENABLED: bool = True
    DEFENSE_RATE_LIMIT: int = 100                # requests allowed per IP...
    DEFENSE_RATE_WINDOW: int = 60                # ...within this many seconds
    DEFENSE_EXCLUDED_PATHS: list[str] = [
        "/docs", "/redoc", "/openapi.json",
        "/health", "/api/v1/health", "/favicon.ico",
    ]

    @field_validator("DEFENSE_EXCLUDED_PATHS", mode="before")
    @classmethod
    def parse_defense_excluded_paths(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v

    # ─── Defense / Tier 1 (Hardening) ─────────────────────────
    # CIDRs of our OWN reverse proxies. Only requests whose direct
    # TCP peer falls in one of these may carry X-Forwarded-For, and
    # even then only the rightmost untrusted hop is used. Empty =
    # never trust XFF (the spoof-proof default).
    TRUSTED_PROXY_CIDRS: str = ""
    # Hard caps on request bodies, enforced BEFORE validation.
    # 256 KB is plenty for any JSON endpoint we expose; auth payloads
    # (login/register/verify/resend) must be tiny — anything bigger is
    # an attack (memory pressure / slow-body DoS).
    DEFENSE_MAX_BODY_BYTES: int = 256 * 1024
    DEFENSE_MAX_BODY_AUTH_BYTES: int = 8 * 1024

    # ─── Defense / Tier 1 (Cost-aware limits, Part C) ────────
    # Endpoints that SEND EMAIL or CREATE ACCOUNTS have a real cost
    # per call; the generic 60/min IP bucket is not enough. Sliding
    # 1-hour windows, per-identifier (email) and per-IP.
    COST_WINDOW_SECONDS: int = 3600
    COST_REGISTER_PER_EMAIL: int = 3      # new-account creation / OTP mail
    COST_REGISTER_PER_IP: int = 10
    COST_RESEND_PER_EMAIL: int = 3        # OTP mail per account
    COST_RESEND_PER_IP: int = 10
    COST_CONTACT_PER_EMAIL: int = 2       # admin-inbox + reply-mail cost
    COST_CONTACT_PER_IP: int = 5

    # ─── Defense / Tier 1 (Prompt-injection guard, Part C) ───
    # AI-bound input (chat) is checked for prompt-injection patterns.
    # Graduated: 1 pattern family → shadow alert only (legitimate
    # security discussion must not be blocked); 2+ families, or any
    # family + obfuscation → blocked (400).
    PROMPT_GUARD_ENABLED: bool = True
    PROMPT_GUARD_BLOCK_FAMILIES: int = 2

    # ─── Defense / Tier 2 (Session lifecycle, Part D) ─────────
    # Real session management: every login mints a session id (sid)
    # embedded in BOTH tokens; the registry tracks active sessions per
    # user. Logout REVOKES the session (access+refresh die at once).
    # Refresh ROTATES the refresh token (replayed/rotated tokens are
    # rejected). Per-user active-session cap evicts the oldest.
    SESSION_REGISTRY_ENABLED: bool = True
    SESSION_MAX_ACTIVE: int = 5

    # ─── Defense / Tier 2 (Per-user limits, Part D) ───────────
    # IP budgets price NETWORK abuse; user budgets price ACCOUNT
    # abuse (a compromised/shared account hammering endpoints from
    # one IP, or a logged-in user flooding refresh/engagement APIs).
    DEFENSE_USER_LIMITS_ENABLED: bool = True
    DEFENSE_USER_RATE_LIMIT: int = 120        # requests/minute per user
    DEFENSE_USER_RATE_WINDOW: int = 60
    DEFENSE_REFRESH_RATE_LIMIT: int = 10      # refresh calls/minute per user

    # ─── Defense / Tier 2 (Alert persistence, Part D) ─────────
    # The live alert ring (in-memory, 200) is the ops feed; a
    # background flush mirrors medium/high-severity alerts into the
    # durable audit_log table so the defense record survives
    # restarts.
    ALERT_PERSISTENCE_ENABLED: bool = True
    ALERT_PERSISTENCE_INTERVAL_SECONDS: int = 5

    # ─── Advanced Validation (Optional) ───────────────────────
    ADVANCED_VALIDATION_ENABLED: bool = False
    ADVANCED_VALIDATION_THRESHOLD: int = 30      # block threshold (0-100)

    # ─── Defense / Tier 2 (AI Behavioral Analysis) ────────────
    DEFENSE_ANOMALY_CONTAMINATION: float = 0.1
    DEFENSE_ANOMALY_N_ESTIMATORS: int = 100
    DEFENSE_ANOMALY_MODEL_PATH: str = "storage/models/anomaly_detector.pkl"
    DEFENSE_ANOMALY_MIN_SAMPLES: int = 50

    # ─── Defense / Tier 3 (Generative AI) ─────────────────────
    # When True, blocked requests additionally trigger a background
    # Tier 3 response (virtual patch + alert + optional IP block).
    # The LLM runs in mock mode unless an API key is configured.
    DEFENSE_TIER3_ENABLED: bool = True
    DEFENSE_BLOCK_THRESHOLD: float = 0.8
    DEFENSE_LLM_PROVIDER: str = "openai"
    DEFENSE_LLM_MODEL: str = "gpt-4-turbo"
    DEFENSE_LLM_MAX_TOKENS: int = 2048
    DEFENSE_LLM_TEMPERATURE: float = 0.2

    # ─── Defense / Abuse Detection ────────────────────────────
    ABUSE_MAX_FAILED_LOGINS: int = 5             # failed logins...
    ABUSE_FAILED_LOGIN_WINDOW: int = 300         # ...within 5 minutes
    ABUSE_MAX_403_ERRORS: int = 10               # 403 errors...
    ABUSE_FORBIDDEN_WINDOW: int = 600            # ...within 10 minutes
    ABUSE_BLOCK_DURATION: int = 3600             # block duration (1 hour)

    # ─── Defense / IP Logger ──────────────────────────────────
    IP_LOGGER_MAX_HISTORY: int = 100             # last 100 requests per IP
    IP_LOGGER_TTL: int = 86400                   # retention (24h)

    # ─── Defense / Incident Logging ───────────────────────────
    INCIDENT_MAX_HISTORY: int = 100              # last 100 incidents per IP
    INCIDENT_TTL: int = 604800                   # retention (1 week)

    # ─── Monitoring / Prometheus ──────────────────────────────
    PROMETHEUS_ENABLED: bool = True
    PROMETHEUS_METRICS_PATH: str = "/metrics"

    # ─── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()

# Validate critical security settings at import time
if not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32:
    # FAIL CLOSED: with a missing or trivially weak key, every JWT the API
    # issues (including admin tokens) can be forged by anyone who knows the
    # key. Refusing to start is the only safe behaviour.
    raise RuntimeError(
        "FATAL: SECRET_KEY is missing or too short (< 32 chars). "
        "JWT tokens would be forgeable. Generate one with: "
        "python -c \"import secrets; print(secrets.token_hex(32))\" — "
        "and set it in backend/.env. Refusing to start the application."
    )
