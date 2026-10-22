"""/healthz (Stage 2 section 9): db, redis (when configured), workers via a short ping."""
from __future__ import annotations

import time

from django.conf import settings
from django.db import connection

_cache = {"at": 0.0, "workers": 0}


def _db_ok() -> bool:
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


def _redis_ok() -> bool | None:
    if not settings.REDIS_URL:
        return None  # not configured (in-memory channels and eager tasks)
    try:
        import redis

        return bool(redis.Redis.from_url(settings.REDIS_URL, socket_timeout=1).ping())
    except Exception:  # noqa: BLE001
        return False


def _workers() -> int:
    from sentinel.celery import app

    if settings.CELERY_TASK_ALWAYS_EAGER or app.conf.task_always_eager:
        return 1  # tasks run in-process: there is no separate worker to count
    if time.monotonic() - _cache["at"] < 10:
        return _cache["workers"]
    try:
        from sentinel.celery import app

        replies = app.control.inspect(timeout=1).ping() or {}
        count = len(replies)
    except Exception:  # noqa: BLE001
        count = 0
    _cache.update(at=time.monotonic(), workers=count)
    return count


def health_report() -> dict:
    db, redis_ok, workers = _db_ok(), _redis_ok(), _workers()
    ok = db and (redis_ok is not False) and (workers >= 1)
    return {"ok": ok, "db": db, "redis": redis_ok, "workers": workers}
