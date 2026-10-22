"""Submission business rules (Stage 2 section 5.3). The only callers that change status go through pipeline.state."""
from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.db import transaction

from devices.models import Command
from pipeline.events import emit
from pipeline.state import set_status
from pipeline.tasks import enqueue_pipeline

from .models import AnalystAction, Sample, Submission, Verdict


def sample_path(sha256: str) -> Path:
    return settings.SENTINEL["MEDIA_SAMPLES"] / sha256[:2] / f"{sha256}.apk"


def summary_of(explanation: str) -> str:
    """First two sentences, at most 200 characters (CONTRACTS / Stage 2 section 5.3)."""
    parts = [p.strip() for p in explanation.replace("\n", " ").split(". ") if p.strip()]
    text = ". ".join(parts[:2])
    if text and not text.endswith("."):
        text += "."
    return text[:200]


def effective_label(sub: Submission) -> str | None:
    """The latest analyst override wins; otherwise the current verdict's label."""
    override = AnalystAction.objects.filter(submission=sub, kind="override").order_by("-created_at", "-id").first()
    if override is not None:
        return override.to_label
    current = Verdict.objects.filter(submission=sub, is_current=True).first()
    return current.label if current else None


def current_verdict(sub: Submission) -> Verdict | None:
    return Verdict.objects.filter(submission=sub, is_current=True).select_related("analysis").first()


def create_submission(device, data: dict) -> tuple[Submission, bool, dict | None]:
    """Returns (submission, need_upload, cached_verdict_summary)."""
    sha = data["apk_sha256"]
    from evalkit.simulate import wants_fresh

    fresh = wants_fresh(data["package_name"])   # demo "Simulate": run the whole pipeline again
    # A device rescan reports the same installed files again: reuse the existing submission, do not duplicate it.
    existing = None if fresh else (Submission.objects.filter(device=device, sample__sha256=sha, status="verdict_ready")
                .select_related("sample").order_by("-created_at").first())
    if existing is not None:
        cached = current_verdict(existing)
        summary = {"label": cached.label, "confidence": cached.confidence,
                   "summary": summary_of(cached.payload.get("explanation", ""))} if cached else None
        return existing, False, summary
    with transaction.atomic():
        sample, _ = Sample.objects.get_or_create(sha256=sha, defaults={"size_bytes": data["apk_size_bytes"]})
        sub = Submission.objects.create(
            device=device, sample=sample, package_name=data["package_name"],
            app_label=data.get("app_label", "") or "", version_name=data.get("version_name", "") or "",
            version_code=data.get("version_code", 0) or 0, installer_package=data.get("installer_package"),
            first_install_time=data.get("first_install_time"),
            requested_permissions=data.get("requested_permissions", []), split_count=data.get("split_count", 0) or 0,
            status="received")
        emit(sub, "intake", "submission_received",
             f"Submission received for {sub.package_name}", data={"sha256": sha, "device_id": str(device.id)},
             type_="submission.created")

        cached = None if fresh else _cached_verdict(sample)
        if cached is not None:
            payload = dict(cached.payload, submission_id=str(sub.id))
            Verdict.objects.create(
                submission=sub, analysis=cached.analysis, label=cached.label, score=cached.score,
                confidence=cached.confidence, payload=payload, provider_name=cached.provider_name,
                provider_version=cached.provider_version, fallback_from=cached.fallback_from, is_current=True)
            set_status(sub, "verdict_ready")
            summary = {"label": cached.label, "confidence": cached.confidence,
                       "summary": summary_of(payload.get("explanation", ""))}
            Command.objects.create(device=device, type="verdict_notify", payload={
                "submission_id": str(sub.id), "package_name": sub.package_name, "app_label": sub.app_label,
                "label": cached.label, "confidence": cached.confidence, "summary": summary["summary"]})
            emit(sub, "intake", "cache_hit", "Verdict reused from an earlier analysis of the same file",
                 data={"analysis_id": cached.analysis_id})
            from pipeline.tasks import post_verdict

            transaction.on_commit(lambda: post_verdict.apply_async(args=[str(sub.id)]))
            return sub, False, summary

        if sample.file_path and Path(sample.file_path).exists():
            set_status(sub, "queued")
            enqueue_pipeline(sub.id)
            return sub, False, None

        set_status(sub, "awaiting_upload")
        emit(sub, "intake", "awaiting_upload", "Waiting for the phone to send the app file")
        return sub, True, None


def _cached_verdict(sample: Sample) -> Verdict | None:
    return (Verdict.objects.filter(submission__sample=sample, is_current=True,
                                   analysis__analysis_version=settings.SENTINEL["ANALYSIS_VERSION"])
            .select_related("analysis").order_by("-created_at", "-id").first())


