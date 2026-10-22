"""The only place that changes Submission.status (CONTRACTS section 3)."""
from __future__ import annotations

from .events import emit

STATUS_LABELS = {
    "received": "Received",
    "awaiting_upload": "Sending file",
    "queued": "Waiting in queue",
    "static_analysis": "Inspecting the app",
    "dynamic_analysis": "Running a safe test",
    "reasoning": "Working out a verdict",
    "verdict_ready": "Done",
    "error": "Something went wrong",
}

IN_PROGRESS = ("awaiting_upload", "queued", "static_analysis", "dynamic_analysis", "reasoning")

ALLOWED = {
    "received": {"awaiting_upload", "queued", "verdict_ready"},
    "awaiting_upload": {"queued", "error"},
    "queued": {"static_analysis", "error"},
    "static_analysis": {"dynamic_analysis", "reasoning", "error"},
    "dynamic_analysis": {"reasoning", "error"},
    "reasoning": {"verdict_ready", "dynamic_analysis", "error"},
    "verdict_ready": {"queued"},   # analyst re-analyze
    "error": {"queued"},           # analyst re-analyze
}


class InvalidTransition(Exception):
    pass


def set_status(sub, new: str, *, emit_event: bool = True, **fields) -> None:
    old = sub.status
    if old != new and new not in ALLOWED.get(old, set()):
        raise InvalidTransition(f"{old} -> {new} is not allowed")
    sub.status = new
    for key, value in fields.items():
        setattr(sub, key, value)
    sub.save()
    if emit_event and old != new:
        emit(sub, "system", "status_changed", f"{STATUS_LABELS[old]} -> {STATUS_LABELS[new]}",
             data={"from": old, "to": new, "status": new, "status_label": STATUS_LABELS[new]},
             type_="submission.status_changed")
