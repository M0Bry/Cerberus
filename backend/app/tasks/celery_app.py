"""
Celery Application — Background task processing for AI operations.
"""

from celery import Celery  # type: ignore[import-untyped]

from app.core.config import settings

celery_app = Celery(
    "cerberus",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,      # 1 hour max per task
    task_soft_time_limit=3000,  # 50 min soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

# Auto-discover tasks in the tasks package
celery_app.autodiscover_tasks(["app.tasks"])
