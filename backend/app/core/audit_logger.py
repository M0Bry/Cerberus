"""Audit Trail — every action logged to DB + file + immutable."""

import uuid

import structlog

from app.db.models.audit_log import AuditLog

logger = structlog.get_logger()


class AuditLogger:
    @staticmethod
    async def log(
        db,  # SQLAlchemy AsyncSession (untyped to avoid circular import)
        user_id: str | None = None,
        action: str = "",
        resource_type: str = "",
        resource_id: str = "",
        ip_address: str = "",
        details: dict | None = None,
        risk_flag: bool = False,
    ) -> AuditLog:
        entry = AuditLog(
            id=str(uuid.uuid4()),
            user_id=user_id,
            action=action,
            description=f"{action}: {resource_type}/{resource_id}",
            ip_address=ip_address,
            details=details or {},
        )
        db.add(entry)
        logger.info(
            "audit_log",
            action=action,
            user=user_id,
            resource=resource_type,
        )
        return entry
