"""Store and broadcast a pipeline event. Only call this where the step really happens (CONTRACTS section 6)."""
from __future__ import annotations

from datetime import timezone as dt_tz

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction


def envelope(ev, submission_id: str | None, type_: str) -> dict:
    return {
        "v": 1,
        "event_id": ev.id,
        "type": type_,
        "ts": ev.ts.astimezone(dt_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "submission_id": submission_id,
        "stage": ev.stage,
        "step": ev.step,
        "level": ev.level,
        "message": ev.message,
        "data": ev.data,
    }


def emit(submission, stage: str, step: str, message: str, level: str = "info",
         data: dict | None = None, type_: str = "pipeline.event"):
    from .models import PipelineEvent

    ev = PipelineEvent.objects.create(
        submission=submission, stage=stage, step=step, level=level, message=message, data=data or {})
    sid = str(submission.id) if submission else None
    payload = envelope(ev, sid, type_)

    def _send():
        layer = get_channel_layer()
        if layer is None:
            return
        groups = ["dashboard"] + ([f"submission.{sid}", f"device.{submission.device_id}"] if sid else [])
        for group in groups:
            async_to_sync(layer.group_send)(group, {"type": "sentinel.event", "payload": payload})

    transaction.on_commit(_send)  # never broadcast something that was rolled back
    return ev
