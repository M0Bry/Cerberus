"""One-shot DB seed: plans + admin (idempotent — safe to re-run).

Cross-platform: works from any machine/OS. Reads DATABASE_URL from
backend/.env (or the DATABASE_URL environment variable if set) and admin
credentials from SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD (defaulting to the
standard project admin).

Usage (from any working directory):
    python scripts/live_tests/res_seed_db.py
"""
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))


def _load_env_file() -> None:
    """Load backend/.env into os.environ (real env vars win).

    The app's Settings reads its env file relative to the CWD, so without
    this the script would fail to start from any directory other than
    backend/.
    """
    p = BACKEND_DIR / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


_load_env_file()

import asyncpg  # noqa: E402
from app.core.security import hash_password  # noqa: E402


def _db_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise SystemExit(
            "DATABASE_URL not found — create backend/.env from "
            "backend/.env.example and set DATABASE_URL to your database."
        )
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def main():
    plans = [
        ("plan-starter", "Starter", "A first, honest look at your exposure.",
         5900, "usd", "MONTH", True),
        ("plan-professional", "Professional",
         "For teams that assess on a rhythm, not once.", 18900, "usd", "MONTH", True),
        ("plan-enterprise", "Enterprise",
         "For organizations with complex environments.", 0, "usd", "MONTH", False),
    ]

    admin_email = os.environ.get("SEED_ADMIN_EMAIL", "admin@cerberus-ai.com")
    admin_pw = os.environ.get("SEED_ADMIN_PASSWORD", "Admin!zoHBF-1dlBnVVK22")

    conn = await asyncpg.connect(_db_url())
    try:
        for pid, name, desc, cents, cur, interval, active in plans:
            await conn.execute(
                """INSERT INTO plans
                   (id, name, description, price_cents, currency, "interval",
                    is_active, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7, now())
                   ON CONFLICT (id) DO UPDATE SET
                     name=EXCLUDED.name, description=EXCLUDED.description,
                     price_cents=EXCLUDED.price_cents, currency=EXCLUDED.currency,
                     "interval"=EXCLUDED."interval", is_active=EXCLUDED.is_active""",
                pid, name, desc, cents, cur, interval, active,
            )
        print("plans seeded")

        admin_id = "admin-cerberus-root"
        hashed = hash_password(admin_pw)
        existing = await conn.fetchval(
            "SELECT 1 FROM users WHERE email=$1", admin_email
        )
        if existing:
            await conn.execute(
                "UPDATE users SET hashed_password=$1, role='ADMIN', status='VERIFIED' "
                "WHERE email=$2",
                hashed, admin_email,
            )
            print("admin updated")
        else:
            await conn.execute(
                """INSERT INTO users
                   (id, full_name, email, company_name, job_title,
                    hashed_password, role, status, mfa_enabled,
                    created_at, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,'ADMIN','VERIFIED', false,
                           now(), now())""",
                admin_id, "Cerberus Admin", admin_email, "Cerberus AI", "Security",
                hashed,
            )
            print("admin created")
        print(f"ready — admin: {admin_email}")
    finally:
        await conn.close()


asyncio.run(main())
