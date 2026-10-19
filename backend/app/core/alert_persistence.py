"""
Defense-alert persistence (Tier 2, Part D).

The live alert ring (in-memory, 200 entries) is the OPS feed — it is
lost on restart. This module mirrors every medium/high-severity
alert into the durable ``audit_log`` table on a short interval so the
defense record survives process restarts and joins the existing audit
history (queryable by IP, user, action).

Design notes:
* PULL-based: the flush reads the ring via get_security_alerts() and
  tracks the highest alert sequence it has persisted — no changes to
  the (synchronous, hot-path) record_security_alert call sites.
* Best-effort: a DB failure logs and retries on the next tick; it
  never raises into the app.
* Test-safe: the live loop is NOT started under pytest (the app's
  session factory points at the configured DB, which in the test
  process must not receive defense-alert rows); persist_new_alerts()
  accepts an injected session for direct unit testing.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = structlog.get_logger()

# low -> informational only (stays in the live feed); medium/high are
# the ones that must survive a restart.
_SEVERITY_MAP = {
    "low": "info",
    "medium": "warning",
    "high": "critical",
}

_SEQ_RE = re.compile(r"alert-(\d+)")


def _seq(alert: dict) -> int:
    m = _SEQ_RE.search(alert.get("id", ""))
    return int(m.group(1)) if m else 0


def _should_persist(alert: dict) -> bool:
    return alert.get("severity") in ("medium", "high")


def format_alert_for_audit(alert: dict) -> str:
    """Compact, grep-friendly description line for the audit row."""
    reasons = alert.get("reasons") or []
    reason_txt = " | ".join(str(r) for r in reasons[:3])
    return (
        f"[defense:{alert.get('attack_type', 'unknown')}] "
        f"{alert.get('title', '')} "
        f"(blocked={alert.get('blocked')}, "
        f"risk={alert.get('risk_score')}, "
        f"conf={alert.get('confidence')})"
        + (f" :: {reason_txt}" if reason_txt else "")
    )


async def persist_new_alerts(
    session: Optional[AsyncSession] = None,
    _state: Optional[dict] = None,
) -> int:
    """
    Flush new persistable alerts from the live ring into audit_log.

    Returns the number of rows written. ``session`` is injected in
    tests; the live loop passes None and a session is opened from the
    app factory. ``_state`` carries the persisted-sequence cursor
    across calls (the live loop owns its own state dict).
    """
    if _state is None:
        _state = module_state
    state = _state

    from app.api.v1.middleware.defense_middleware import get_security_alerts

    items = get_security_alerts(limit=200)
    new = [a for a in items if _seq(a) > state["last_seq"]]
    if not new:
        return 0

    from app.db.session import async_session_factory

    written = 0
    if session is None:
        async with async_session_factory() as owned:
            written = await _write_rows(owned, new, state)
            await owned.commit()
    else:
        written = await _write_rows(session, new, state)
    return written


async def _write_rows(
    session: AsyncSession, new: list, state: dict
) -> int:
    from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity

    written = 0
    for alert in new:
        if not _should_persist(alert):
            state["last_seq"] = max(state["last_seq"], _seq(alert))
            continue
        try:
            row = AuditLog(
                action=AuditAction.SECURITY_ALERT,
                severity=AuditSeverity(_SEVERITY_MAP[alert["severity"]]),
                description=format_alert_for_audit(alert)[:1000],
                ip_address=alert.get("source_ip"),
            )
            session.add(row)
            written += 1
            state["last_seq"] = _seq(alert)
        except Exception as e:  # noqa: BLE001
            logger.error("alert_persist_row_failed", error=str(e))
    if written:
        await session.flush()
    return written


# Cursor owned by the live loop (per process).
module_state: dict = {"last_seq": 0}


async def alert_persistence_loop() -> None:
    """Background flush (started in the app lifespan)."""
    while True:
        await asyncio.sleep(settings.ALERT_PERSISTENCE_INTERVAL_SECONDS)
        try:
            n = await persist_new_alerts()
            if n:
                logger.info("defense_alerts_persisted", count=n)
        except Exception as e:  # noqa: BLE001 — never kill the loop
            logger.error("alert_persistence_failed", error=str(e))
