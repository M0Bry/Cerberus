"""
Email Utilities — provider-routed transactional email (SMTP / SendGrid /
console) + OTP & contact-reply templates.

Provider selection (settings.EMAIL_PROVIDER):
  auto     → SMTP when configured, console otherwise (dev-friendly default)
  smtp     → SMTP; if credentials are missing it warns loudly and falls
             back to console so the flow never silently dies
  sendgrid → SendGrid v3 API (SENDGRID_API_KEY)
  console  → always print to the backend console (local development)
"""

import email.mime.multipart  # noqa: F401  (re-exported for existing imports)
import email.mime.text
import smtplib  # noqa: F401
import ssl

import aiosmtplib
import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger()


# ─── Provider resolution ─────────────────────────────────────────────────


def _resolved_provider() -> str:
    """Return the effective provider after the auto/explicit rules."""
    provider = (settings.EMAIL_PROVIDER or "auto").strip().lower()
    if provider == "auto":
        return "smtp" if (settings.SMTP_USER and settings.SMTP_FROM_EMAIL) else "console"
    return provider


def _smtp_configured() -> bool:
    return bool(settings.SMTP_USER and settings.SMTP_FROM_EMAIL)


# ─── Transport: console ──────────────────────────────────────────────────


def _console_send(to_email: str, subject: str, code: str | None = None) -> bool:
    """Dev-mode transport: print the message to the backend console."""
    if code:
        logger.warning(
            "dev_mode_otp_no_smtp_configured",
            to=to_email,
            code=code,
            expires_in_seconds=settings.OTP_EXPIRE_SECONDS,
        )
        print(  # noqa: T201 — deliberate console output for local dev
            f"\n{'=' * 62}\n"
            f"  [CERBERUS DEV] OTP for {to_email}:\n"
            f"    {code}\n"
            f"  (console email provider — code printed instead of email)\n"
            f"{'=' * 62}\n"
        )
    else:
        logger.info("console_email", to=to_email, subject=subject)
        print(  # noqa: T201
            f"\n{'=' * 62}\n"
            f"  [CERBERUS DEV] Email (console) to {to_email}\n"
            f"  Subject: {subject}\n"
            f"{'=' * 62}\n"
        )
    return True


# ─── Transport: SMTP ─────────────────────────────────────────────────────


async def _smtp_send(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
) -> bool:
    message = email.mime.multipart.MIMEMultipart("alternative")
    message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    message["To"] = to_email
    message["Subject"] = subject
    if text_body:
        message.attach(email.mime.text.MIMEText(text_body, "plain"))
    message.attach(email.mime.text.MIMEText(html_body, "html"))

    # Port 465 → implicit TLS; otherwise STARTTLS (when enabled).
    implicit_tls = settings.SMTP_PORT == 465
    try:
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            start_tls=not implicit_tls and settings.SMTP_USE_TLS,
            use_tls=implicit_tls,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            timeout=15,
        )
        logger.info("email_sent", to=to_email, subject=subject, provider="smtp")
        return True
    except Exception as e:  # noqa: BLE001
        logger.error(
            "email_send_error", to=to_email, provider="smtp", error=str(e)
        )
        return False


# ─── Transport: SendGrid ─────────────────────────────────────────────────


async def _sendgrid_send(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
) -> bool:
    content = [{"type": "text/html", "value": html_body}]
    if text_body:
        content.append({"type": "text/plain", "value": text_body})
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {
            "email": settings.SMTP_FROM_EMAIL or "noreply@cerberus-ai.local",
            "name": settings.SMTP_FROM_NAME,
        },
        "subject": subject,
        "content": content,
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{settings.SENDGRID_API_URL.rstrip('/')}/v3/mail/send",
                json=payload,
                headers={
                    "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
        if resp.status_code >= 300:
            logger.error(
                "email_send_error",
                to=to_email,
                provider="sendgrid",
                status=resp.status_code,
                body=resp.text[:300],
            )
            return False
        logger.info("email_sent", to=to_email, subject=subject, provider="sendgrid")
        return True
    except Exception as e:  # noqa: BLE001
        logger.error(
            "email_send_error", to=to_email, provider="sendgrid", error=str(e)
        )
        return False


# ─── Public API ──────────────────────────────────────────────────────────


async def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
) -> bool:
    """Send an email through the configured provider."""
    provider = _resolved_provider()

    if provider == "console" or (
        provider == "smtp" and not _smtp_configured()
    ):
        if provider == "smtp":
            logger.warning(
                "smtp_provider_selected_but_unconfigured — falling back to console"
            )
        return _console_send(to_email, subject)

    if provider == "smtp":
        return await _smtp_send(to_email, subject, html_body, text_body)

    if provider == "sendgrid":
        if not settings.SENDGRID_API_KEY:
            logger.warning(
                "sendgrid_provider_selected_but_no_api_key — falling back to console"
            )
            return _console_send(to_email, subject)
        return await _sendgrid_send(to_email, subject, html_body, text_body)

    logger.warning("unknown_email_provider_falling_back_to_console", provider=provider)
    return _console_send(to_email, subject)


async def send_otp_email(to_email: str, otp: str) -> bool:
    """Send the OTP verification email (provider-routed).

    Console mode prints the code to the backend console so the full
    registration/verification flow stays testable end-to-end without
    mail infrastructure.
    """
    if _resolved_provider() == "console":
        return _console_send(to_email, "Cerberus AI — Verify Your Email Address", code=otp)

    seconds = settings.OTP_EXPIRE_SECONDS
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
            <p class="warning">⚠️ This code expires in {seconds} seconds. Do not share it with anyone.</p>  # noqa: E501
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
        "Cerberus AI - Email Verification\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in {seconds} seconds.\n"
        "Do not share it with anyone."
    )

    return await send_email(
        to_email=to_email,
        subject="Cerberus AI — Verify Your Email Address",
        html_body=html_body,
        text_body=text_body,
    )


async def send_admin_otp_email(to_email: str, otp: str) -> bool:
    """Send the admin-portal 2FA code (provider-routed).

    Distinct wording from the registration OTP: this is the second factor
    of the hardened admin login, not an email-verification step.
    """
    if _resolved_provider() == "console":
        return _console_send(
            to_email, "Cerberus AI — Admin Sign-In Verification", code=otp
        )

    seconds = settings.OTP_EXPIRE_SECONDS
    html_body = f"""  # noqa: E501
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}  # noqa: E501
            .container {{ max-width: 600px; margin: 0 auto; background: #1a1a2e; border-radius: 12px; padding: 40px; border: 1px solid #ff6b6b55; }}  # noqa: E501
            .logo {{ text-align: center; margin-bottom: 30px; }}
            .logo h1 {{ color: #00d4ff; font-size: 28px; }}
            .otp-box {{ background: #0d1117; border: 2px solid #00d4ff; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }}
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
            <h2 style="color: #fff;">Restricted Access — Sign-In Verification</h2>
            <p>An administrator account is attempting to sign in to the Cerberus control panel.</p>  # noqa: E501
            <p>Enter the one-time code below to complete sign-in.</p>
            <div class="otp-box">
                <div class="otp-code">{otp}</div>
            </div>
            <p class="warning">⚠️ This code expires in {seconds} seconds and can be used once. Do not share it with anyone.</p>  # noqa: E501
            <p>If this was not you, change your password immediately and contact security.</p>
            <div class="footer">
                <p>Cerberus AI — Intelligent Cybersecurity Platform</p>
                <p>This is an automated message. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """  # noqa: E501

    text_body = (
        "Cerberus AI - Restricted Access: Sign-In Verification\n\n"
        f"Your one-time sign-in code is: {otp}\n\n"
        f"This code expires in {seconds} seconds and can be used once.\n"
        "Do not share it with anyone.\n"
        "If this was not you, change your password immediately."
    )

    return await send_email(
        to_email=to_email,
        subject="Cerberus AI — Admin Sign-In Verification",
        html_body=html_body,
        text_body=text_body,
    )


async def send_contact_reply_email(
    to_email: str, reply_text: str, original_subject: str
) -> bool:
    """Deliver an admin's reply to an UNREGISTERED contact sender
    (guests have no account, so no in-app notification is possible)."""
    safe_reply = reply_text.replace("\r\n", "\n")
    html_body = (
        "<div style=\"font-family:Arial;background:#0a0a1a;color:#e0e0e0;padding:20px;\">"
        "<div style=\"max-width:600px;margin:0 auto;background:#1a1a2e;border-radius:12px;padding:40px;border:1px solid #00d4ff33;\">"
        "<h1 style=\"color:#00d4ff;text-align:center;font-size:24px;\">🛡️ CERBERUS AI</h1>"
        "<h2 style=\"color:#fff;\">We received your message</h2>"
        f"<p><em>Regarding: {original_subject}</em></p>"
        f"<div style=\"background:#0d1117;border:1px solid #00d4ff33;border-radius:8px;padding:20px;margin:20px 0;white-space:pre-line;\">{safe_reply}</div>"  # noqa: E501
        "<div style=\"color:#666;font-size:12px;text-align:center;\">"
        "<p>Cerberus AI — Intelligent Cybersecurity Platform</p>"
        "<p>This is an automated message. Please do not reply.</p>"
        "</div></div></div>"
    )
    return await send_email(
        to_email=to_email,
        subject=f"Cerberus AI — Re: {original_subject}",
        html_body=html_body,
        text_body=(
            f"Cerberus AI replied to your message '{original_subject}':\n\n"
            f"{safe_reply}\n"
        ),
    )
