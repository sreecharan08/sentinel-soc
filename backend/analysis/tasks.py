"""Stage 3 pipeline entry points. Called from pipeline.tasks (Celery) so they run on the `analysis` queue."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from pipeline.events import emit
from pipeline.state import set_status

from .engine import EvidenceInvalid, new_context, run_static
from .models import Analysis

log = logging.getLogger(__name__)


def run_static_analysis_impl(sub_id: str) -> None:
    from submissions.models import Submission

    sub = Submission.objects.select_related("sample", "device").get(pk=sub_id)
    if sub.status != "queued":
        return
    set_status(sub, "static_analysis")
    emit(sub, "static_analysis", "started", "Static analysis started")
    version = settings.SENTINEL["ANALYSIS_VERSION"]

    existing = Analysis.objects.filter(sample=sub.sample, analysis_version=version).first()
    if existing is not None:
        emit(sub, "static_analysis", "finished", "Reused cached analysis of the same file",
             data={"analysis_id": existing.id, "cached": True})
        return

    sample_path = sub.sample.file_path
    if not sample_path or not Path(sample_path).exists():
        set_status(sub, "error", error_code="sample_missing", error_detail="The app file is not in storage")
        emit(sub, "static_analysis", "failed", "App file missing from storage", level="error")
        return

    workdir = Path(settings.SENTINEL["WORK_DIR"]) / sub.sample.sha256
    workdir.mkdir(parents=True, exist_ok=True)
    started = timezone.now()

    def _emit(stage, step, message, level="info", data=None):
        emit(sub, stage, step, message, level=level, data=data or {})

    meta = {"package_name": sub.package_name, "requested_permissions": sub.requested_permissions,
            "app_label": sub.app_label, "split_count": sub.split_count}
    ctx = new_context(sub.sample.sha256, sample_path, str(workdir), meta, _emit)
    try:
        evidence = run_static(ctx)
    except EvidenceInvalid as exc:
        set_status(sub, "error", error_code="evidence_invalid", error_detail=str(exc))
        emit(sub, "static_analysis", "failed", f"Evidence failed schema validation: {exc}", level="error")
        return
    except Exception as exc:  # noqa: BLE001 - recorded on the submission, never a silent failure
        log.exception("static analysis failed for %s", sub.id)
        set_status(sub, "error", error_code="analysis_failed", error_detail=str(exc)[:500])
        emit(sub, "static_analysis", "failed", f"Static analysis failed: {exc}", level="error")
        return

    if sub.split_count:
        ctx.partial_reasons.append("split_apks_not_analyzed")
        evidence["partial"] = True
        evidence["partial_reasons"] = list(ctx.partial_reasons)
    analysis = Analysis.objects.create(sample=sub.sample, analysis_version=version, evidence=evidence,
                                       partial=evidence["partial"], started_at=started, finished_at=timezone.now())
    (workdir / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    by_sev: dict[str, int] = {}
    for sig in evidence["signals"]:
        by_sev[sig["severity"]] = by_sev.get(sig["severity"], 0) + 1
    emit(sub, "static_analysis", "signals_extracted", f"{len(evidence['signals'])} signals extracted",
         data={"count": len(evidence["signals"]), "by_severity": by_sev})
    emit(sub, "static_analysis", "finished",
         "Static analysis finished" + (" (partial)" if evidence["partial"] else ""),
         level="warn" if evidence["partial"] else "info",
         data={"analysis_id": analysis.id, "partial_reasons": evidence["partial_reasons"]})


def run_dynamic_analysis_impl(sub_id: str, plan: list) -> bool:
    """Stretch goal (Stage 3 section 6). Returns True only if a dynamic run actually happened.

    The emulator runner is not part of this build. When DYNAMIC_ENABLED is false (the default) the verdict is
    final without it, and the evidence chain records that the step was skipped.
    """
    from submissions.models import Submission

    sub = Submission.objects.get(pk=sub_id)
    if not settings.SENTINEL["DYNAMIC_ENABLED"]:
        emit(sub, "dynamic_analysis", "skipped", "Dynamic analysis is disabled on this server",
             data={"enabled": False, "plan": plan})
        return False
    emit(sub, "dynamic_analysis", "skipped", "No emulator runner is installed in this build; static verdict kept",
         level="warn", data={"enabled": True, "plan": plan})
    return False
