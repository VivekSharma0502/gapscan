"""Celery application. Scan state lives in Postgres, so Redis is only the job queue."""

from typing import Any

from celery import Celery
from celery.signals import worker_process_init, worker_ready

from app.core import db
from app.core.config import settings
from app.repos.scanner import sweep_abandoned_workspaces

celery_app = Celery("gapscan",broker=settings.redis_url, include=["app.workers.tasks"])

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
    # Repo scans can run for minutes, so their own queue lets production give them a separate
    # worker and keep website scans moving.
    task_routes={"scans.run_repo": {"queue": "repo_scans"}},
)


@worker_ready.connect
def clean_up_after_a_crash(**_kwargs: Any) -> None:
    sweep_abandoned_workspaces()


@worker_process_init.connect
def reset_db_pool(**_kwargs: Any) -> None:
    # Forked workers must not share the parent's database connections.
    db.engine.dispose(close=False)
