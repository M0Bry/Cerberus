"""Contact Service — stores public 'Contact Us' submissions for the admin.

Anti-abuse: the public form is rate-limited per sender IP in the database
(persists across restarts, works with multiple workers) on top of the
generic middleware limiter.
"""

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.cost_guard import CostGuard
from app.core.exceptions import RateLimitError
from app.db.models.contact_message import ContactMessage
from app.db.models.notification import Notification, NotificationType
from app.schemas.contact import (
    ContactMessageCreate,
    ContactMessageItem,
    ContactMessageListResponse,
    ContactReplyResponse,
)
from app.utils.email import send_contact_reply_email

logger = structlog.get_logger()

# Public form: max N messages per IP per window (spam protection).
_CONTACT_IP_LIMIT = 5
_CONTACT_IP_WINDOW_MINUTES = 10


class ContactService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_message(
        self,
        payload: ContactMessageCreate,
        client_ip: str | None,
        user_agent: str | None,
        user_id: str | None = None,
    ) -> None:
        """Store a public contact message after the per-IP spam check.

        ``user_id`` is set when the sender is a logged-in registered
        account; ``None`` means an unregistered landing-page visitor.
        """
        if client_ip:
            since = datetime.now(timezone.utc) - timedelta(
                minutes=_CONTACT_IP_WINDOW_MINUTES
            )
            recent = (
                await self.db.execute(
                    select(func.count(ContactMessage.id)).where(
                        ContactMessage.ip_address == client_ip,
                        ContactMessage.created_at >= since,
                    )
                )
            ).scalar_one()
            if recent >= _CONTACT_IP_LIMIT:
                raise RateLimitError(
                    "Too many contact messages from this address. "
                    "Please try again later or email us directly."
                )

        # ── Cost-aware per-email limit (Tier 1, Part C) ─────────
        # A contact submission is stored in the ADMIN inbox AND can
        # trigger a reply mail — a real cost. The per-IP check above
        # does not stop one sender address abused across many IPs
        # (botnet / proxy pool) from flooding the admin inbox.
        ok, _retry = await CostGuard.charge(
            "contact",
            str(payload.email),
            settings.COST_CONTACT_PER_EMAIL,
        )
        if not ok:
            CostGuard.record_abuse_alert(
                operation="contact",
                identifier=str(payload.email),
                ip=client_ip,
            )
            raise RateLimitError(
                "Too many messages from this email address. "
                "Please try again later or email us directly."
            )

        msg = ContactMessage(
            id=str(uuid.uuid4()),
            name=payload.name,
            email=str(payload.email),
            subject=payload.subject,
            message=payload.message,
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        self.db.add(msg)
        await self.db.flush()
        logger.info(
            "contact_message_received",
            message_id=msg.id,
            email=msg.email,
            registered=user_id is not None,
            ip=client_ip,
        )

    async def reply_message(self, message_id: str, reply_text: str) -> ContactReplyResponse:
        """Admin replies to a contact message.

        Registered senders get the reply as a notification on their
        Notifications page; unregistered guests get it by email at the
        address they provided (a failed email send never loses the
        reply — it is stored and the failure is reported in ``delivery``).
        """
        msg = (
            await self.db.execute(
                select(ContactMessage).where(ContactMessage.id == message_id)
            )
        ).scalar_one_or_none()
        if not msg:
            from app.core.exceptions import NotFoundError

            raise NotFoundError("Contact message not found")

        now = datetime.now(timezone.utc)  # noqa: UP017
        msg.reply = reply_text
        msg.replied_at = now
        if not msg.is_read:
            msg.is_read = True
            msg.read_at = now
        await self.db.flush()

        if msg.user_id:
            notif = Notification(
                id=str(uuid.uuid4()),
                user_id=msg.user_id,
                engagement_id=None,
                notification_type=NotificationType.INFO,
                title="Reply from the Cerberus team",
                message=reply_text,
                action_url=None,
            )
            self.db.add(notif)
            await self.db.flush()
            logger.info(
                "contact_reply_notified",
                message_id=msg.id,
                user_id=msg.user_id,
                notification_id=notif.id,
            )
            delivery, note = "notification", "Delivered to the user's Notifications page."
        else:
            sent = await send_contact_reply_email(msg.email, reply_text, msg.subject)
            if sent:
                delivery, note = "email", f"Emailed to {msg.email}."
            else:
                delivery, note = "none", (
                    "Stored, but the guest email could not be delivered "
                    "(mail provider error — see backend logs)."
                )
                logger.error("contact_reply_email_failed", message_id=msg.id, to=msg.email)

        return ContactReplyResponse(
            message=ContactMessageItem.model_validate(msg),
            delivery=delivery,
            delivery_note=note,
        )

    # ── Admin ────────────────────────────────────────────────────────────

    async def list_messages(
        self, page: int, page_size: int, unread_only: bool = False
    ) -> ContactMessageListResponse:
        base = select(ContactMessage)
        if unread_only:
            base = base.where(ContactMessage.is_read.is_(False))

        total = (
            (await self.db.execute(select(func.count()).select_from(base.subquery())))
        ).scalar_one()

        unread_total = (
            (
                await self.db.execute(
                    select(func.count(ContactMessage.id)).where(
                        ContactMessage.is_read.is_(False)
                    )
                )
            ).scalar_one()
        )

        rows = (
            await self.db.execute(
                base.order_by(ContactMessage.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return ContactMessageListResponse(
            items=[ContactMessageItem.model_validate(r) for r in rows],
            total=total,
            unread=unread_total,
            page=page,
            page_size=page_size,
        )

    async def mark_read(self, message_id: str) -> ContactMessageItem:
        msg = (
            await self.db.execute(
                select(ContactMessage).where(ContactMessage.id == message_id)
            )
        ).scalar_one_or_none()
        if not msg:
            from app.core.exceptions import NotFoundError

            raise NotFoundError("Contact message not found")
        if not msg.is_read:
            msg.is_read = True
            msg.read_at = datetime.now(timezone.utc)  # noqa: UP017
            await self.db.flush()
        return ContactMessageItem.model_validate(msg)
