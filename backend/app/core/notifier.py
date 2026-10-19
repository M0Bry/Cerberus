"""
Notifier — Multi-channel notification system for threats & alerts.

بيوفر:
- Multiple channels (console, slack, discord, telegram, email, webhook)
- Multiple levels (info, warning, error, critical)
- Rate limiting per channel
- Retry logic
- Template-based messages
- Redis-backed tracking
- Async dispatch (parallel sends)
- Channel enable/disable

الفكرة:
- بنسجل channels (Slack, Discord, Email, ...)
- كل notification بتروح على كل القنوات المطلوبة
- Rate limiting عشان نمنع spam
- Retry لو القناة فشلت

الاستخدام:
- auto_mitigation.py
- graduated_response.py
- abuse_detector.py
- monitoring
- alerting
"""

import asyncio
import json
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import httpx
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class NotifLevel(str, Enum):
    """مستويات الإشعار."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotifChannel(str, Enum):
    """قنوات الإشعار."""
    CONSOLE = "console"
    WEBHOOK = "webhook"       # generic
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"


class Notifier:
    """
    Multi-Channel Notifier.

    الفكرة:
    - كل channel له config مختلف
    - الـ notify() بترسل على كل القنوات بالتوازي
    - كل قناة فيها rate limiting + retry
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    RATE_LIMIT_WINDOW = 60       # دقيقة
    MAX_NOTIFS_PER_WINDOW = 20   # max 20 notifications/دقيقة لكل قناة
    RETRY_ATTEMPTS = 2
    RETRY_DELAY = 1.0
    REQUEST_TIMEOUT = 10.0       # ثواني

    HISTORY_TTL = 86400 * 7      # أسبوع
    MAX_HISTORY = 1000

    # ─── Default Emoji per Level ──────────────────────────
    LEVEL_EMOJI = {
        NotifLevel.INFO: "ℹ️",
        NotifLevel.WARNING: "⚠️",
        NotifLevel.ERROR: "❌",
        NotifLevel.CRITICAL: "🚨",
    }

    LEVEL_COLOR = {
        NotifLevel.INFO: "#3498db",       # blue
        NotifLevel.WARNING: "#f39c12",    # orange
        NotifLevel.ERROR: "#e74c3c",      # red
        NotifLevel.CRITICAL: "#c0392b",   # dark red
    }

    # ─── Redis Keys ───────────────────────────────────────
    RATE_KEY_PREFIX = "notif:rate:"
    HISTORY_KEY = "notif:history"

    # ─── In-Memory Channel Config ─────────────────────────
    # ملاحظة: الـ sensitive data (webhooks, SMTP pass) بتتقرأ من settings
    _channels: Dict[str, Dict[str, Any]] = {}
    _enabled: Dict[str, bool] = {}

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """Lazy Redis client."""
        if cls._redis_client is None:
            try:
                cls._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            except Exception as e:
                logger.error("notifier_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _rate_key(channel: str) -> str:
        return f"{Notifier.RATE_KEY_PREFIX}{channel}"

    # ═══════════════════════════════════════════════════════
    #  Channel Management
    # ═══════════════════════════════════════════════════════

    @classmethod
    def configure_channel(
        cls,
        channel: str,
        config: Dict[str, Any],
        *,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        بيضبط channel.

        Args:
            channel: اسم القناة (console/webhook/slack/discord/telegram/email)
            config: الإعدادات الخاصة بالقناة
            enabled: مفعلة؟

        Returns:
            dict فيه success
        """
        try:
            if not channel:
                return {"success": False, "error": "missing_channel"}

            cls._channels[channel] = config or {}
            cls._enabled[channel] = enabled

            logger.info(
                "notifier_channel_configured",
                channel=channel,
                enabled=enabled,
            )

            return {
                "success": True,
                "channel": channel,
                "enabled": enabled,
            }

        except Exception as e:
            logger.error("notifier_configure_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    def enable_channel(cls, channel: str) -> Dict[str, Any]:
        """بيفعّل channel."""
        if channel not in cls._channels:
            return {"success": False, "error": "channel_not_configured"}

        cls._enabled[channel] = True
        return {"success": True, "channel": channel, "enabled": True}

    @classmethod
    def disable_channel(cls, channel: str) -> Dict[str, Any]:
        """بيعطّل channel."""
        cls._enabled[channel] = False
        return {"success": True, "channel": channel, "enabled": False}

    @classmethod
    def is_channel_enabled(cls, channel: str) -> bool:
        """بيتحقق لو القناة مفعلة."""
        return cls._enabled.get(channel, False)

    @classmethod
    def list_channels(cls) -> Dict[str, Any]:
        """بيرجع قائمة القنوات."""
        return {
            channel: {
                "enabled": cls._enabled.get(channel, False),
                "configured": channel in cls._channels,
            }
            for channel in set(cls._channels) | set(cls._enabled)
        }

    # ═══════════════════════════════════════════════════════
    #  Rate Limiting
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _check_rate_limit(cls, channel: str) -> bool:
        """
        بيتحقق لو الـ channel وصل للحد الأقصى.

        Returns:
            True لو مسموح، False لو rate limited
        """
        client = cls.get_client()
        if not client:
            return True  # اسمح لو Redis مش متاح

        try:
            rate_key = cls._rate_key(channel)
            count = int(await client.get(rate_key) or 0)

            if count >= cls.MAX_NOTIFS_PER_WINDOW:
                return False

            # زوّد العداد
            await client.incr(rate_key)
            await client.expire(rate_key, cls.RATE_LIMIT_WINDOW)

            return True

        except Exception as e:
            logger.debug("notifier_rate_limit_failed", error=str(e))
            return True

    # ═══════════════════════════════════════════════════════
    #  Message Building
    # ═══════════════════════════════════════════════════════

    @classmethod
    def _build_message(
        cls,
        level: str,
        title: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """بيبني رسالة منسقة."""
        try:
            level_enum = NotifLevel(level.lower())
        except ValueError:
            level_enum = NotifLevel.INFO

        emoji = cls.LEVEL_EMOJI[level_enum]
        color = cls.LEVEL_COLOR[level_enum]

        # نص عادي
        text_parts = [f"{emoji} [{level_enum.value.upper()}] {title}"]
        text_parts.append("")
        text_parts.append(message)

        if details:
            text_parts.append("")
            text_parts.append("Details:")
            for k, v in details.items():
                text_parts.append(f"  • {k}: {v}")

        text = "\n".join(text_parts)

        return {
            "level": level_enum.value,
            "emoji": emoji,
            "color": color,
            "title": title,
            "message": message,
            "text": text,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "details": details or {},
        }

    # ═══════════════════════════════════════════════════════
    #  Channel Senders
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _send_console(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على console/log."""
        try:
            level = msg["level"]
            log_fn = getattr(logger, level if level != "warning" else "warning")

            log_fn(
                "notifier_console",
                title=msg["title"],
                message=msg["message"],
                details=msg["details"],
            )
            return {"success": True, "channel": "console"}
        except Exception as e:
            return {"success": False, "channel": "console", "error": str(e)}

    @classmethod
    async def _send_webhook(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على generic webhook."""
        url = config.get("url")
        if not url:
            return {"success": False, "channel": "webhook", "error": "missing_url"}

        try:
            payload = {
                "level": msg["level"],
                "title": msg["title"],
                "message": msg["message"],
                "text": msg["text"],
                "timestamp": msg["timestamp"],
                "details": msg["details"],
            }

            headers = config.get("headers", {})
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"

            async with httpx.AsyncClient(timeout=cls.REQUEST_TIMEOUT) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()

            return {"success": True, "channel": "webhook"}

        except Exception as e:
            return {"success": False, "channel": "webhook", "error": str(e)}

    @classmethod
    async def _send_slack(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على Slack webhook."""
        url = config.get("webhook_url") or config.get("url")
        if not url:
            return {"success": False, "channel": "slack", "error": "missing_webhook"}

        try:
            payload = {
                "text": f"{msg['emoji']} *{msg['title']}*",
                "attachments": [
                    {
                        "color": msg["color"],
                        "text": msg["message"],
                        "fields": [
                            {"title": k, "value": str(v), "short": True}
                            for k, v in msg["details"].items()
                        ] if msg["details"] else [],
                        "footer": msg["timestamp"],
                    }
                ],
            }

            async with httpx.AsyncClient(timeout=cls.REQUEST_TIMEOUT) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()

            return {"success": True, "channel": "slack"}

        except Exception as e:
            return {"success": False, "channel": "slack", "error": str(e)}

    @classmethod
    async def _send_discord(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على Discord webhook."""
        url = config.get("webhook_url") or config.get("url")
        if not url:
            return {"success": False, "channel": "discord", "error": "missing_webhook"}

        try:
            # Discord color: convert hex to int
            try:
                color_hex = msg["color"].lstrip("#")
                color_int = int(color_hex, 16)
            except (ValueError, AttributeError):
                color_int = 0x3498db

            payload = {
                "embeds": [
                    {
                        "title": f"{msg['emoji']} {msg['title']}",
                        "description": msg["message"],
                        "color": color_int,
                        "fields": [
                            {"name": k, "value": str(v), "inline": True}
                            for k, v in msg["details"].items()
                        ] if msg["details"] else [],
                        "footer": {"text": msg["timestamp"]},
                    }
                ],
            }

            async with httpx.AsyncClient(timeout=cls.REQUEST_TIMEOUT) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()

            return {"success": True, "channel": "discord"}

        except Exception as e:
            return {"success": False, "channel": "discord", "error": str(e)}

    @classmethod
    async def _send_telegram(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على Telegram."""
        bot_token = config.get("bot_token")
        chat_id = config.get("chat_id")

        if not bot_token or not chat_id:
            return {
                "success": False,
                "channel": "telegram",
                "error": "missing_bot_token_or_chat_id",
            }

        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

            payload = {
                "chat_id": chat_id,
                "text": msg["text"],
                "parse_mode": "HTML",
            }

            async with httpx.AsyncClient(timeout=cls.REQUEST_TIMEOUT) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()

            return {"success": True, "channel": "telegram"}

        except Exception as e:
            return {"success": False, "channel": "telegram", "error": str(e)}

    @classmethod
    async def _send_email(
        cls,
        msg: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """بيبعت على Email via SMTP."""
        try:
            smtp_host = config.get("smtp_host") or getattr(settings, "SMTP_HOST", None)
            smtp_port = config.get("smtp_port") or getattr(settings, "SMTP_PORT", 587)
            smtp_user = config.get("smtp_user") or getattr(settings, "SMTP_USER", None)
            smtp_pass = config.get("smtp_password") or getattr(settings, "SMTP_PASSWORD", None)
            use_tls = config.get("use_tls", True)

            from_email = config.get("from_email") or smtp_user
            to_emails = config.get("to_emails", [])

            if isinstance(to_emails, str):
                to_emails = [to_emails]

            if not all([smtp_host, smtp_user, from_email, to_emails]):
                return {
                    "success": False,
                    "channel": "email",
                    "error": "missing_email_config",
                }

            # Build message
            email_msg = MIMEMultipart("alternative")
            email_msg["Subject"] = f"{msg['emoji']} {msg['title']}"
            email_msg["From"] = from_email
            email_msg["To"] = ", ".join(to_emails)

            # HTML version
            html_body = cls._build_email_html(msg)
            email_msg.attach(MIMEText(html_body, "html"))

            # Send (بـ run_in_executor عشان SMTP مش async)
            def _send_sync():
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    if use_tls:
                        server.starttls()
                    if smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.sendmail(from_email, to_emails, email_msg.as_string())

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _send_sync)

            return {"success": True, "channel": "email"}

        except Exception as e:
            return {"success": False, "channel": "email", "error": str(e)}

    @classmethod
    def _build_email_html(cls, msg: Dict[str, Any]) -> str:
        """بيبني HTML للـ email."""
        details_html = ""
        if msg["details"]:
            rows = "".join(
                f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
                for k, v in msg["details"].items()
            )
            details_html = f"""
            <table style="border-collapse: collapse; margin-top: 16px;">
                {rows}
            </table>
            """

        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="border-left: 4px solid {msg['color']}; padding-left: 16px;">
                <h2 style="color: {msg['color']}; margin: 0;">
                    {msg['emoji']} {msg['title']}
                </h2>
                <p style="font-size: 14px; color: #333; margin-top: 12px;">
                    {msg['message']}
                </p>
                {details_html}
                <p style="font-size: 12px; color: #999; margin-top: 24px;">
                    {msg['timestamp']}
                </p>
            </div>
        </body>
        </html>
        """

    # ═══════════════════════════════════════════════════════
    #  Main Notify
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def notify(
        cls,
        title: str,
        message: str,
        *,
        level: str = "info",
        details: Optional[Dict[str, Any]] = None,
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        بيبعت إشعار على كل القنوات.

        Args:
            title: عنوان الإشعار
            message: الرسالة
            level: info/warning/error/critical
            details: تفاصيل إضافية
            channels: قائمة القنوات (None = كل المفعّلة)

        Returns:
            dict فيه:
            - sent: قائمة القنوات اللي نجحت
            - failed: قائمة الفشل
            - rate_limited: قائمة اللي اتعمل لها rate limit
        """
        try:
            if not title or not message:
                return {"success": False, "error": "missing_title_or_message"}

            # 1. حدد القنوات
            if channels:
                target_channels = [
                    c for c in channels
                    if c in cls._channels and cls._enabled.get(c, False)
                ]
            else:
                target_channels = [
                    c for c, enabled in cls._enabled.items()
                    if enabled and c in cls._channels
                ]

            if not target_channels:
                # لو مفيش قناة مفعلة، اطبع على console
                if "console" not in cls._channels:
                    cls.configure_channel("console", {})

                # لو لسه مفيش قنوات مفعلة نهائياً
                if not target_channels:
                    target_channels = ["console"]

            # 2. ابنِ الرسالة
            msg = cls._build_message(level, title, message, details)

            # 3. ابعتها على كل القنوات (parallel)
            sent: List[str] = []
            failed: List[Dict[str, Any]] = []
            rate_limited: List[str] = []

            async def _send_one(channel: str) -> Tuple[str, Dict[str, Any]]:
                # rate limit check
                allowed = await cls._check_rate_limit(channel)
                if not allowed:
                    return channel, {"success": False, "rate_limited": True}

                # حدد الـ sender
                senders = {
                    "console": cls._send_console,
                    "webhook": cls._send_webhook,
                    "slack": cls._send_slack,
                    "discord": cls._send_discord,
                    "telegram": cls._send_telegram,
                    "email": cls._send_email,
                }
                sender = senders.get(channel)
                if not sender:
                    return channel, {"success": False, "error": "unknown_channel"}

                config = cls._channels.get(channel, {})

                # retry logic
                last_error = None
                for attempt in range(cls.RETRY_ATTEMPTS + 1):
                    try:
                        result = await sender(msg, config)
                        if result.get("success"):
                            return channel, result
                        last_error = result.get("error", "unknown")
                    except Exception as e:
                        last_error = str(e)

                    if attempt < cls.RETRY_ATTEMPTS:
                        await asyncio.sleep(cls.RETRY_DELAY)

                return channel, {"success": False, "error": last_error}

            # شغل بالتوازي
            tasks = [_send_one(c) for c in target_channels]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception):
                    continue

                channel, result = res

                if result.get("rate_limited"):
                    rate_limited.append(channel)
                elif result.get("success"):
                    sent.append(channel)
                else:
                    failed.append({
                        "channel": channel,
                        "error": result.get("error", "unknown"),
                    })

            # 4. Log
            if level in ("critical", "error"):
                logger.error(
                    "notifier_sent",
                    title=title,
                    level=level,
                    sent=sent,
                    failed_count=len(failed),
                    rate_limited_count=len(rate_limited),
                )
            else:
                logger.info(
                    "notifier_sent",
                    title=title,
                    level=level,
                    sent=sent,
                )

            # 5. سجل في history
            await cls._log_history(msg, sent, failed, rate_limited)

            return {
                "success": True,
                "title": title,
                "level": msg["level"],
                "sent": sent,
                "failed": failed,
                "rate_limited": rate_limited,
                "total_channels": len(target_channels),
                "sent_count": len(sent),
                "notified_at": time.time(),
            }

        except Exception as e:
            logger.error("notifier_notify_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Shortcuts
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def info(
        cls,
        title: str,
        message: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Shortcut لـ info."""
        return await cls.notify(title, message, level="info", **kwargs)

    @classmethod
    async def warning(
        cls,
        title: str,
        message: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Shortcut لـ warning."""
        return await cls.notify(title, message, level="warning", **kwargs)

    @classmethod
    async def error(
        cls,
        title: str,
        message: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Shortcut لـ error."""
        return await cls.notify(title, message, level="error", **kwargs)

    @classmethod
    async def critical(
        cls,
        title: str,
        message: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Shortcut لـ critical."""
        return await cls.notify(title, message, level="critical", **kwargs)

    @classmethod
    async def alert_threat(
        cls,
        entity_type: str,
        entity_value: str,
        *,
        risk_score: int,
        signals: Optional[List[str]] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        إشعار متخصص للتهديدات.

        بيستخدم التنسيق المناسب للـ SOC.
        """
        signals = signals or []

        # حدد الـ level من risk
        if risk_score >= 85:
            level = "critical"
        elif risk_score >= 70:
            level = "error"
        elif risk_score >= 50:
            level = "warning"
        else:
            level = "info"

        details = {
            "entity": f"{entity_type}:{entity_value}",
            "risk_score": risk_score,
            "signals_count": len(signals),
        }

        if signals:
            details["signals"] = ", ".join(signals[:5])

        if action:
            details["action"] = action

        return await cls.notify(
            title=f"Threat Detected: {entity_type.upper()}",
            message=f"Suspicious activity from {entity_value} with risk {risk_score}/100",
            level=level,
            details=details,
        )

    # ═══════════════════════════════════════════════════════
    #  History
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def _log_history(
        cls,
        msg: Dict[str, Any],
        sent: List[str],
        failed: List[Dict[str, Any]],
        rate_limited: List[str],
    ) -> None:
        """بيسجل الإشعار في history."""
        client = cls.get_client()
        if not client:
            return

        try:
            entry = {
                "timestamp": time.time(),
                "level": msg["level"],
                "title": msg["title"],
                "message": msg["message"],
                "sent_channels": sent,
                "failed_count": len(failed),
                "rate_limited_count": len(rate_limited),
            }

            await client.lpush(cls.HISTORY_KEY, json.dumps(entry))
            await client.ltrim(cls.HISTORY_KEY, 0, cls.MAX_HISTORY - 1)
            await client.expire(cls.HISTORY_KEY, cls.HISTORY_TTL)

        except Exception as e:
            logger.debug("notifier_log_history_failed", error=str(e))

    @classmethod
    async def get_history(
        cls,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """بيرجع تاريخ الإشعارات."""
        client = cls.get_client()
        if not client:
            return []

        try:
            raw_list = await client.lrange(cls.HISTORY_KEY, 0, limit - 1)

            history = []
            for raw in raw_list:
                try:
                    history.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            return history

        except Exception as e:
            logger.error("notifier_get_history_failed", error=str(e))
            return []

    # ═══════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_stats(cls) -> Dict[str, Any]:
        """بيرجع إحصائيات الـ notifier."""
        try:
            history = await cls.get_history(limit=1000)

            level_counts: Dict[str, int] = {}
            channel_counts: Dict[str, int] = {}

            for entry in history:
                level = entry.get("level", "unknown")
                level_counts[level] = level_counts.get(level, 0) + 1

                for ch in entry.get("sent_channels", []):
                    channel_counts[ch] = channel_counts.get(ch, 0) + 1

            return {
                "success": True,
                "total_notifications": len(history),
                "level_distribution": level_counts,
                "channel_distribution": channel_counts,
                "configured_channels": list(cls._channels.keys()),
                "enabled_channels": [
                    c for c, enabled in cls._enabled.items()
                    if enabled
                ],
            }

        except Exception as e:
            logger.error("notifier_stats_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Reset
    # ═══════════════════════════════════════════════════════

    @classmethod
    def reset_channels(cls) -> None:
        """بيمسح كل القنوات من الـ memory."""
        cls._channels = {}
        cls._enabled = {}
        logger.info("notifier_channels_reset")

    @classmethod
    async def clear_history(cls) -> None:
        """بيمسح تاريخ الإشعارات."""
        client = cls.get_client()
        if not client:
            return

        try:
            await client.delete(cls.HISTORY_KEY)

            # امسح rate limits
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{cls.RATE_KEY_PREFIX}*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("notifier_history_cleared")

        except Exception as e:
            logger.error("notifier_clear_history_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def notify(
    title: str,
    message: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for Notifier.notify."""
    return await Notifier.notify(title, message, **kwargs)


async def critical(
    title: str,
    message: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for Notifier.critical."""
    return await Notifier.critical(title, message, **kwargs)


async def alert_threat(
    entity_type: str,
    entity_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for Notifier.alert_threat."""
    return await Notifier.alert_threat(entity_type, entity_value, **kwargs)