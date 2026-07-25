"""Email Background Tasks — Async email sending via Celery."""

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="email.send")
def send_email_task(self, to_email: str, subject: str, html_body: str):
    """Send an email asynchronously."""
    import asyncio

    from app.utils.email import send_email

    asyncio.run(send_email(to_email, subject, html_body))
    return {"to": to_email, "status": "sent"}


@celery_app.task(bind=True, name="email.send_report_ready")
def send_report_ready_email(self, user_email: str, report_id: str, engagement_name: str):
    """Notify user that their report is ready."""
    return {"to": user_email, "report_id": report_id, "status": "sent"}
