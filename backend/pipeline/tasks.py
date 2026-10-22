"""Pipeline orchestration (Stage 2 section 4). Each task is guarded by the submission status so retries are safe."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import timedelta

from celery import chain, shared_task
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from jsonschema import Draft202012Validator

from .events import emit
from .state import set_status

log = logging.getLogger(__name__)

SCHEMA_DIR = settings.BASE_DIR.parent / "shared"


def _load_schema(name: str) -> dict:
    import json

    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def enqueue_pipeline(sub_id) -> None:
    """Run the chain after the current transaction commits (never enqueue a row that might roll back)."""

    def _go():
        chain(
            run_static_analysis.si(str(sub_id)),
            run_reasoning.si(str(sub_id), 0),
            finalize_verdict.si(str(sub_id)),
            post_verdict.si(str(sub_id)),
        ).apply_async()

    transaction.on_commit(_go)


@shared_task(name="analysis.tasks.run_static_analysis", autoretry_for=(OSError,), max_retries=3,
             retry_backoff=True, soft_time_limit=120, time_limit=150)
def run_static_analysis(sub_id: str) -> None:
    from analysis.tasks import run_static_analysis_impl

    run_static_analysis_impl(sub_id)


@shared_task(name="pipeline.tasks.run_reasoning")
def run_reasoning(sub_id: str, loop_count: int = 0) -> None:
    """Call the configured Reasoner under a time budget, validate, store a draft Verdict.

    The verification loop is bounded here: dynamic -> reasoning again, at most MAX_VERIFICATION_LOOPS times.
    """
    from submissions.models import Submission, Verdict
    from reasoning.registry import current_backend, get_reasoner
    from reasoning.interface import ReasonContext
    from analysis.models import Analysis

    sub = Submission.objects.select_related("sample").get(pk=sub_id)
    if sub.status not in ("static_analysis", "dynamic_analysis"):
        return
    set_status(sub, "reasoning")
    analysis = Analysis.objects.filter(sample=sub.sample, analysis_version=settings.SENTINEL["ANALYSIS_VERSION"]).first()
    if analysis is None:
        set_status(sub, "error", error_code="evidence_missing", error_detail="No evidence stored for this sample")
        emit(sub, "system", "error", "No evidence stored; cannot reason", level="error")
        return

    budget = settings.SENTINEL["REASONER_TIMEOUT_S"]
    reasoner = get_reasoner(current_backend())
    emit(sub, "reasoning", "started", f"Reasoner {reasoner.name} v{reasoner.version} started",
         data={"provider": reasoner.name, "version": reasoner.version, "loop": loop_count})
    ctx = ReasonContext(submission_id=str(sub.id), budget_seconds=budget, loop_count=loop_count,
                        device_info={"device_id": str(sub.device_id)},
                        dynamic_allowed=settings.SENTINEL["DYNAMIC_ENABLED"]
                        and loop_count < settings.SENTINEL["MAX_VERIFICATION_LOOPS"])
    verdict = _run_with_budget(reasoner, analysis.evidence, ctx, budget)
    if verdict is None or not _valid_verdict(verdict, analysis.evidence):
        fallback_from = reasoner.name
        verdict = get_reasoner("rules").reason(analysis.evidence, ctx)
        verdict["provider"]["fallback_from"] = fallback_from
        emit(sub, "reasoning", "fallback_used",
             f"Reasoner {fallback_from} failed; verdict produced by rule_engine", level="warn",
             data={"fallback_from": fallback_from})

    Verdict.objects.create(
        submission=sub, analysis=analysis, label=verdict["label"], score=verdict["score"],
        confidence=verdict["confidence"], payload=verdict, provider_name=verdict["provider"]["name"],
        provider_version=verdict["provider"]["version"], fallback_from=verdict["provider"].get("fallback_from"),
        is_current=False)

    if verdict.get("needs_more_verification") and ctx.dynamic_allowed:
        from analysis.tasks import run_dynamic_analysis_impl

        set_status(sub, "dynamic_analysis")
        if run_dynamic_analysis_impl(str(sub.id), verdict.get("verification_requests", [])):
            run_reasoning(str(sub.id), loop_count + 1)  # bounded by ctx.dynamic_allowed on the next pass
            return
        set_status(sub, "reasoning")
    elif verdict.get("needs_more_verification"):
        emit(sub, "dynamic_analysis", "skipped", "Dynamic verification requested but disabled on this server")
    emit(sub, "reasoning", "finished", f"Verdict {verdict['label']} (confidence {verdict['confidence']:.0%})",
         data={"label": verdict["label"], "confidence": verdict["confidence"], "provider": verdict["provider"]})


def _run_with_budget(reasoner, evidence, ctx, budget):
    """Returns the verdict dict, or None on timeout / exception. Never raises (Reasoner contract, rule 1)."""
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(reasoner.reason, evidence, ctx)
    try:
        return future.result(timeout=budget)
    except FutureTimeout:
        emit(None, "reasoning", "failed", f"Reasoner {reasoner.name} exceeded {budget}s", level="warn")
        return None
    except Exception:  # noqa: BLE001 - the orchestrator must survive any reasoner
        log.exception("reasoner failed")
        return None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _valid_verdict(verdict: dict, evidence: dict) -> bool:
    """Schema-validate and reject evidence ids that were not in the evidence (Stage 2 section 5)."""
    try:
        Draft202012Validator(_load_schema("verdict.schema.json")).validate(verdict)
    except Exception:  # noqa: BLE001
        return False
    known = {s["id"] for s in evidence.get("signals", [])}
    for tech in verdict.get("techniques", []):
        if any(eid not in known for eid in tech.get("evidence_ids", [])):
            return False
    return verdict.get("label") in ("malicious", "suspicious", "benign", "unknown")


@shared_task(name="pipeline.tasks.finalize_verdict")
def finalize_verdict(sub_id: str) -> None:
    from submissions.models import Submission, Verdict
    from submissions.services import effective_label
    from devices.models import Command

    sub = Submission.objects.select_related("device", "sample").get(pk=sub_id)
    if sub.status != "reasoning":
        return
    with transaction.atomic():
        draft = Verdict.objects.filter(submission=sub, is_current=False).order_by("-created_at", "-id").first()
        if draft is None:
            set_status(sub, "error", error_code="verdict_missing", error_detail="No verdict was produced")
            return
        Verdict.objects.filter(submission=sub, is_current=True).update(is_current=False)
        draft.is_current = True
        draft.save(update_fields=["is_current"])
        label = effective_label(sub)
        payload = _notify_payload(sub, draft, label)
        Command.objects.create(device=sub.device, type="verdict_notify", payload=payload)
        set_status(sub, "verdict_ready", error_code="", error_detail="")
    emit(sub, "verdict", "stored", f"Verdict stored: {label}",
         data={"label": label, "confidence": draft.confidence, "provider": draft.provider_name},
         type_="verdict.ready")
    emit(sub, "verdict", "notified_device", "Verdict queued for the phone", data={"command": "verdict_notify"})


def _notify_payload(sub, verdict, label: str) -> dict:
    summary = " ".join(verdict.payload.get("explanation", "").split(". ")[:2])[:200]
    return {
        "submission_id": str(sub.id),
        "package_name": sub.package_name,
        "app_label": sub.app_label,
        "label": label,
        "confidence": verdict.confidence,
        "summary": summary,
    }


@shared_task(name="pipeline.tasks.post_verdict")
def post_verdict(sub_id: str) -> None:
    """Remediation policy and rule generation. Failures here never change the verdict (Stage 6 section 4)."""
    from submissions.models import Submission

    sub = Submission.objects.get(pk=sub_id)
    for step_name, fn in (("remediation", _policy_step), ("rules", _rules_step)):
        try:
            fn(sub)
        except Exception as exc:  # noqa: BLE001
            log.exception("post_verdict %s failed", step_name)
            emit(sub, step_name, "failed", f"{step_name} step failed: {exc}", level="error")


def _policy_step(sub):
    from remediation.services import evaluate_policy

    evaluate_policy(sub)


def _rules_step(sub):
    from rules.generators import generate_for

    generate_for(sub)


@shared_task(name="pipeline.tasks.requeue_stale")
def requeue_stale() -> int:
    """Beat task: re-enqueue submissions stuck in `queued` for more than 2 minutes (Stage 2 section 9)."""
    from submissions.models import Submission

    cutoff = timezone.now() - timedelta(minutes=2)
    stale = list(Submission.objects.filter(status="queued", updated_at__lt=cutoff).values_list("id", flat=True))
    for sid in stale:
        enqueue_pipeline(sid)
    return len(stale)


