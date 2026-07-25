"""
Email Utilities — Send verification emails, notifications, and reports.
"""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib
import structlog

from app.core.config import settings

logger = structlog.get_logger()


async def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
) -> bool:
    """
    Send an email using SMTP.

    Args:
        to_email: Recipient email address.
        subject: Email subject line.
        html_body: HTML email body.
        text_body: Plain text fallback.

    Returns:
        True if sent successfully, False otherwise.
    """
    try:
        message = MIMEMultipart("alternative")
        message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        message["To"] = to_email
        message["Subject"] = subject

        if text_body:
            message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            start_tls=True,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
        )

        logger.info("email_sent", to=to_email, subject=subject)
        return True

    except Exception as e:
        logger.error("email_send_error", to=to_email, error=str(e))
        return False


async def send_otp_email(to_email: str, otp: str) -> bool:
    """Send OTP verification email."""

    html_body = f"""  # noqa: E501
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}  # noqa: E501
            .container {{ max-width: 600px; margin: 0 auto; background: #1a1a2e; border-radius: 12px; padding: 40px; border: 1px solid #00d4ff33; }}  # noqa: E501
            .logo {{ text-align: center; margin-bottom: 30px; }}
            .logo h1 {{ color: #00d4ff; font-size: 28px; }}
            .otp-box {{ background: #0d1117; border: 2px solid #00d4ff; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }}  # noqa: E501
            .otp-code {{ font-size: 36px; font-weight: bold; color: #00d4ff; letter-spacing: 8px; }}
            .warning {{ color: #ff6b6b; font-size: 14px; margin-top: 20px; }}
            .footer {{ color: #666; font-size: 12px; margin-top: 30px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>🛡️ CERBERUS AI</h1>
            </div>
            <h2 style="color: #fff;">Email Verification</h2>
            <p>A security verification code has been sent to your registered email address.</p>  # noqa: E501
            <p>Please enter the verification code below to activate your account.</p>
            <div class="otp-box">
                <div class="otp-code">{otp}</div>
            </div>
            <p class="warning">⚠️ This code expires in 5 minutes. Do not share it with anyone.</p>  # noqa: E501
            <p>If you did not create an account, please ignore this email.</p>
            <div class="footer">
                <p>Cerberus AI — Intelligent Cybersecurity Platform</p>
                <p>This is an automated message. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """  # noqa: E501

    text_body = (
        f"Cerberus AI - Email Verification\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in 5 minutes.\n"
        f"Do not share it with anyone."
    )

    return await send_email(
        to_email=to_email,
        subject="Cerberus AI — Verify Your Email Address",
        html_body=html_body,
        text_body=text_body,
    )
