"""Rule lifecycle (Stage 6 sections 3 and 6): approve, retire, edit as a new version, FP test, export, feedback."""
from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from datetime import date
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from pipeline.events import emit
from sentinel.errors import ApiError
from submissions.models import AnalystAction, Submission
from submissions.services import effective_label

from . import sigma as sigma_mod
from .generators import self_test_and_fp, validate_yara_text
from .models import GeneratedRule, RuleMatch


def _active_dir(kind: str) -> Path:
    path = settings.SENTINEL["RULES_DIR"] / "active" / kind
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def active_path(rule: GeneratedRule) -> Path:
    ext = ".yar" if rule.kind == "yara" else ".yml"
    return _active_dir(rule.kind) / f"{rule.name}{ext}"


def approve(rule: GeneratedRule, user, note: str = "") -> GeneratedRule:
    if rule.status != "draft":
        raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"status": rule.status})
    fp_passed = rule.fp_test.get("status") == "passed"
    if not fp_passed and not note.strip():
        raise ApiError("validation_error", "Approve anyway needs a note: the false-positive test did not pass.", 400,
                       {"fp_status": rule.fp_test.get("status", "not_run")})
    if rule.kind == "yara":
        validate_yara_text(rule.content)
    else:
        try:
            sigma_mod.load(rule.content)
        except sigma_mod.UnsupportedSigma as exc:
            raise ApiError("validation_error", f"Sigma rule is not valid: {exc}", 400)
    try:
        _write_atomic(active_path(rule), rule.content)
        if rule.kind == "yara":
            from analysis.analyzers.reputation import compile_rules

            compile_rules()  # recompile the whole set so a bad combination is caught now, not on a live scan
    except Exception as exc:  # noqa: BLE001 - the rule stays a draft; the dashboard shows the error
        try:
            active_path(rule).unlink(missing_ok=True)
        except OSError:
            pass
        raise ApiError("internal_error", f"Could not activate the rule: {exc}", 500)
    rule.status, rule.approved_by, rule.approved_at, rule.approve_note = "approved", user, timezone.now(), note
    rule.save(update_fields=["status", "approved_by", "approved_at", "approve_note"])
    if rule.source_submission_id:
        emit(rule.source_submission, "rules", "approved", f"Rule {rule.name} approved",
             data={"rule_id": str(rule.id), "fp_test": rule.fp_test.get("status")})
    return rule


def retire(rule: GeneratedRule, user, note: str = "") -> GeneratedRule:
    if rule.status != "approved":
        raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"status": rule.status})
    try:
        active_path(rule).unlink(missing_ok=True)
    except OSError as exc:
        raise ApiError("internal_error", f"Could not remove the active rule file: {exc}", 500)
    rule.status, rule.retired_at = "retired", timezone.now()
    rule.approve_note = (rule.approve_note + " | retired: " + note).strip(" |")
    rule.save(update_fields=["status", "retired_at", "approve_note"])
    if rule.source_submission_id:
        emit(rule.source_submission, "rules", "retired", f"Rule {rule.name} retired",
             data={"rule_id": str(rule.id)})
    return rule


def edit_as_new_version(rule: GeneratedRule, content: str, user) -> GeneratedRule:
    if rule.kind == "yara":
        validate_yara_text(content)
    else:
        try:
            sigma_mod.load(content)
        except sigma_mod.UnsupportedSigma as exc:
            raise ApiError("validation_error", f"Sigma rule is not valid: {exc}", 400)
    version = rule.version + 1
    while GeneratedRule.objects.filter(name=rule.name, version=version).exists():
        version += 1
    new = GeneratedRule.objects.create(
        kind=rule.kind, name=rule.name, content=content, status="draft", level=rule.level,
        source_submission=rule.source_submission, source_sha256=rule.source_sha256, verdict=rule.verdict,
        version=version, parent=rule, meta={**rule.meta, "edited_by": user.get_username() if user else None},
        fp_test={"status": "not_run"})
    if rule.kind == "yara" and rule.source_submission_id and rule.source_submission.sample.file_path:
        new.fp_test = {**self_test_and_fp(content, rule.source_submission.sample.file_path)["fp_test"],
                       "run_at": date.today().isoformat()}
        new.save(update_fields=["fp_test"])
    return new


def run_fp_test(rule: GeneratedRule) -> GeneratedRule:
    if rule.kind != "yara" or not rule.source_submission_id:
        return rule
    result = self_test_and_fp(rule.content, rule.source_submission.sample.file_path)
    rule.fp_test = {**result["fp_test"], "run_at": date.today().isoformat()}
    rule.save(update_fields=["fp_test"])
    return rule


def mark_false_positive(match: RuleMatch, user) -> RuleMatch:
    match.false_positive, match.marked_by = True, user
    match.save(update_fields=["false_positive", "marked_by"])
    rule = match.rule
    rule.needs_review = True
    rule.save(update_fields=["needs_review"])
    return match


def match_approved_sigma(sub: Submission) -> list[RuleMatch]:
    """Evaluate every approved Sigma rule against this submission's install metadata (Stage 6 section 5.4)."""
    from analysis.models import Analysis

    analysis = Analysis.objects.filter(sample=sub.sample, analysis_version=settings.SENTINEL["ANALYSIS_VERSION"]).first()
    signer = ((analysis.evidence.get("static", {}).get("signing") or {}).get("cert_sha256") or "") if analysis else ""
    event = {
        "package_name": sub.package_name, "app_label": sub.app_label, "version_name": sub.version_name,
        "installer_package": sub.installer_package or "", "requested_permissions": list(sub.requested_permissions),
        "apk_sha256": sub.sample.sha256, "signer_sha256": signer, "device_name": sub.device.name,
    }
    matches = []
    for rule in GeneratedRule.objects.filter(kind="sigma", status="approved"):
        try:
            if sigma_mod.evaluate(sigma_mod.load(rule.content), event):
                match = RuleMatch.objects.create(rule=rule, submission=sub)
                matches.append(match)
                emit(sub, "rules", "matched", f"Approved rule {rule.name} matched this install",
                     level="warn", data={"rule_id": str(rule.id), "match_id": match.id}, type_="rule.generated")
        except sigma_mod.UnsupportedSigma:
            continue
    return matches


def feedback_for(sub: Submission) -> list[dict]:
    """Past analyst overrides for the same package name (fed to the reasoner as ReasonContext.analyst_feedback)."""
    rows = AnalystAction.objects.filter(kind="override", submission__package_name=sub.package_name) \
        .exclude(submission=sub).order_by("-created_at")[:10]
    return [{"submission_id": str(r.submission_id), "from": r.from_label, "to": r.to_label, "note": r.note,
             "at": r.created_at.isoformat()} for r in rows]


def export_zip() -> bytes:
    buf = io.BytesIO()
    approved = GeneratedRule.objects.filter(status="approved").order_by("name")
    manifest = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule in approved:
            path = active_path(rule)
            ext = path.suffix
            arc = f"{rule.kind}/{rule.name}{ext}"
            zf.writestr(arc, rule.content)
            manifest.append({"id": str(rule.id), "name": rule.name, "kind": rule.kind, "version": rule.version,
                             "sha256": hashlib.sha256(rule.content.encode()).hexdigest(),
                             "approved_by": rule.approved_by.get_username() if rule.approved_by else None,
                             "approved_at": rule.approved_at.isoformat() if rule.approved_at else None})
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buf.getvalue()


def rule_row(rule: GeneratedRule) -> dict:
    return {
        "id": str(rule.id), "name": rule.name, "kind": rule.kind, "status": rule.status, "level": rule.level,
        "version": rule.version, "source_sha256": rule.source_sha256, "needs_review": rule.needs_review,
        "fp_test": rule.fp_test, "created_at": rule.created_at.isoformat(),
        "approved_at": rule.approved_at.isoformat() if rule.approved_at else None,
        "effective_label": effective_label(rule.source_submission) if rule.source_submission_id else None,
    }
