"""Remediation lifecycle (Stage 6 section 3). The server never assumes success before the device reports it."""
from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from dashboard.settings_store import effective_settings
from devices.models import Command
from pipeline.events import emit
from sentinel.errors import ApiError
from submissions.models import AnalystAction, Submission
from submissions.services import current_verdict, effective_label

from .models import RemediationRequest
from .policy import evaluate

RESULT_TO_STATE = {"uninstalled": "completed", "declined": "declined", "failed": "failed"}
TERMINAL = {"completed", "declined", "failed", "cancelled", "expired"}


def _ttl() -> timedelta:
    return timedelta(hours=settings.SENTINEL["REMEDIATION_TTL_HOURS"])


def evaluate_policy(sub: Submission, origin: str = "auto", user=None) -> RemediationRequest | None:
    """Gather the inputs, run the pure policy, record the decision, and create a request when allowed."""
    verdict = current_verdict(sub)
    if verdict is None:
        return None
    cfg = effective_settings()
    device = sub.device
    now = timezone.now()
    open_exists = RemediationRequest.objects.filter(device=device, package_name=sub.package_name,
                                                    state__in=RemediationRequest.OPEN_STATES).exists()
    declined = RemediationRequest.objects.filter(device=device, package_name=sub.package_name, state="declined",
                                                 resolved_at__gte=now - timedelta(hours=24)).exists()
    recent = RemediationRequest.objects.filter(device=device, created_at__gte=now - timedelta(hours=1)).count()
    decision = evaluate(
        origin, package=sub.package_name, label=effective_label(sub) or verdict.label,
        confidence=verdict.confidence, recommended_action=verdict.payload.get("recommended_action", "none"),
        settings=cfg, hold=sub.remediation_hold, device_last_seen=device.last_seen,
        device_revoked=device.revoked, open_request_exists=open_exists, recent_declined=declined,
        recent_count=recent, protected=set(cfg.get("protected_packages", [])),
        own_package=cfg.get("own_package", "com.sentinel.soc"), now=now)
    emit(sub, "remediation", "policy_evaluated",
         ("Policy allows an uninstall proposal" if decision.allowed else "Policy blocked an uninstall proposal"),
         level="info" if decision.allowed else "debug",
         data={"origin": origin, "allowed": decision.allowed, "checks": decision.as_snapshot()["checks"]},
         type_="remediation.updated")
    if not decision.allowed:
        return None
    return create_request(sub, origin=origin, user=user, snapshot=decision.as_snapshot())


def create_request(sub: Submission, origin: str, user=None, snapshot: dict | None = None,
                   note: str = "") -> RemediationRequest:
    verdict = current_verdict(sub)
    with transaction.atomic():
        if RemediationRequest.objects.select_for_update().filter(
                device=sub.device, package_name=sub.package_name, state__in=RemediationRequest.OPEN_STATES).exists():
            raise ApiError("state_conflict", "That can't be done in the current state.", 409,
                           {"status": "open_request_exists"})
        rem = RemediationRequest.objects.create(
            submission=sub, device=sub.device, package_name=sub.package_name, app_label=sub.app_label,
            origin=origin, created_by=user, state="pending", policy_snapshot=snapshot or {},
            expires_at=timezone.now() + _ttl(), note=note)
        cmd = Command.objects.create(device=sub.device, type="uninstall_proposed", payload={
            "remediation_id": str(rem.id), "submission_id": str(sub.id), "package_name": sub.package_name,
            "app_label": sub.app_label, "label": effective_label(sub) or (verdict.label if verdict else "unknown"),
            "confidence": verdict.confidence if verdict else 0.0,
            "summary": (verdict.payload.get("explanation", "")[:200] if verdict else ""),
        })
        rem.command = cmd
        rem.save(update_fields=["command"])
        emit(sub, "remediation", "proposed", f"Uninstall proposed for {sub.package_name} ({origin})",
             data={"remediation_id": str(rem.id), "origin": origin, "state": "pending"},
             type_="remediation.updated")
    return rem


def mark_delivered(command: Command) -> None:
    rem = RemediationRequest.objects.filter(command=command, state="pending").first()
    if rem is None:
        return
    rem.state, rem.delivered_at = "delivered", timezone.now()
    rem.save(update_fields=["state", "delivered_at"])
    emit(rem.submission, "remediation", "delivered", "The phone received the uninstall proposal",
         data={"remediation_id": str(rem.id)}, type_="remediation.updated")


def handle_result(rem: RemediationRequest, outcome: str, detail: str = "") -> RemediationRequest:
    new_state = RESULT_TO_STATE[outcome]
    if rem.state in TERMINAL:
        if rem.state == new_state:
            return rem  # idempotent for the same outcome
        raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"state": rem.state})
    if rem.state not in RemediationRequest.OPEN_STATES:
        raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"state": rem.state})
    rem.state = new_state
    rem.resolved_at = timezone.now()
    rem.outcome_detail = detail[:500]
    rem.save(update_fields=["state", "resolved_at", "outcome_detail"])
    level = "info" if new_state in ("completed", "declined") else "warn"
    emit(rem.submission, "remediation", new_state, f"Device reported: {new_state}", level=level,
         data={"remediation_id": str(rem.id), "detail": detail[:200]}, type_="remediation.updated")
    return rem


def cancel(rem: RemediationRequest, user, note: str = "") -> RemediationRequest:
    if rem.state not in RemediationRequest.OPEN_STATES:
        raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"state": rem.state})
    with transaction.atomic():
        rem.state = "cancelled"
        rem.resolved_at = timezone.now()
        rem.note = note or rem.note
        rem.save(update_fields=["state", "resolved_at", "note"])
        Command.objects.create(device=rem.device, type="uninstall_cancelled", payload={
            "remediation_id": str(rem.id), "package_name": rem.package_name})
        AnalystAction.objects.create(submission=rem.submission, user=user, kind="remediation_cancel", note=note)
        emit(rem.submission, "remediation", "cancelled", "An analyst cancelled the uninstall request",
             data={"remediation_id": str(rem.id)}, type_="remediation.updated")
    return rem


def expire_stale() -> int:
    now = timezone.now()
    count = 0
    for rem in RemediationRequest.objects.filter(state__in=RemediationRequest.OPEN_STATES, expires_at__lt=now):
        with transaction.atomic():
            rem.state, rem.resolved_at = "expired", now
            rem.save(update_fields=["state", "resolved_at"])
            Command.objects.create(device=rem.device, type="uninstall_cancelled", payload={
                "remediation_id": str(rem.id), "package_name": rem.package_name})
            emit(rem.submission, "remediation", "expired", "No response within the time limit",
                 data={"remediation_id": str(rem.id)}, type_="remediation.updated")
        count += 1
    return count


def set_hold(sub: Submission, hold: bool, user) -> None:
    sub.remediation_hold = hold
    sub.save(update_fields=["remediation_hold"])
    AnalystAction.objects.create(submission=sub, user=user, kind="hold", note="hold on" if hold else "hold off")
    emit(sub, "remediation", "hold_changed", f"Automatic remediation hold {'set' if hold else 'cleared'}",
         data={"hold": hold})
