"""Celery application. Scan state lives in Postgres, so Redis is only the job queue."""

from typing import Any

from celery import Celery
from celery.signals import worker_process_init

from app.core import db
from app.core.config import settings

celery_app = Celery("scankit", broker=settings.redis_url, include=["app.workers.tasks"])

celery_app.conf.update(
    # Security: JSON only. Accepting pickle would let anyone who can write to Redis run code.
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    timezone="UTC",
    enable_utc=True,
    # A scan takes seconds to minutes, so one worker shouldn't reserve a backlog of them.
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    # Kept under SCAN_STALE_AFTER. Enforced on Linux, where the prefork pool supports it.
    task_time_limit=270,
)


@worker_process_init.connect
def reset_db_pool(**_kwargs: Any) -> None:
    # Forked workers must not share the parent's database connections.
    db.engine.dispose(close=False)
