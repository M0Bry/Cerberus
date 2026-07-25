"""
Email Service — Email sending (SMTP / SendGrid / AWS SES) + templates.
"""

import structlog

from app.core.config import settings
from app.utils.email import send_email, send_otp_email

logger = structlog.get_logger()


class EmailService:
    """Handles all email operations."""

    async def send_verification_email(self, email: str, otp: str) -> bool:
        return await send_otp_email(email, otp)

    async def send_welcome_email(self, email: str, name: str) -> bool:
        html = f"""
        <div style="font-family:Arial;background:#0a0a1a;color:#e0e0e0;padding:20px;">
        <div style="max-width:600px;margin:0 auto;background:#1a1a2e;border-radius:12px;padding:40px;border:1px solid rgba(0,212,255,0.2);">
            <h2 style="color:#00d4ff;text-align:center;">🛡️ Welcome to Cerberus AI!</h2>
            <p>Hello {name},</p>
            <p>Your account has been verified. You can now begin using Cerberus AI
            for intelligent security assessments.</p>
            <p style="text-align:center;margin:30px 0;"><a href="{settings.CORS_ORIGINS[0]}/dashboard" style="background:linear-gradient(135deg,#00d4ff,#6366f1);color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;">Go to Dashboard</a></p>  # noqa: E501
        </div>
        </div>
        """  # noqa: E501
        return await send_email(email, "Welcome to Cerberus AI", html)

    # … rest of the methods unchanged
