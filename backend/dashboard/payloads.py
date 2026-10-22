"""Payload builders shared by the JSON API and the server-rendered pages (one source of truth for both)."""
from __future__ import annotations

from datetime import timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

from devices.models import Device
from pipeline.events import envelope
from pipeline.models import PipelineEvent
from pipeline.state import IN_PROGRESS
from remediation.models import RemediationRequest
from rules.models import GeneratedRule
from rules.services import rule_row as _rule_row
from submissions.models import AnalystAction, Sample, Submission, Verdict
from submissions.services import current_verdict, effective_label

from .settings_store import effective_settings

LABELS = ("malicious", "suspicious", "benign", "unknown")


def iso(dt) -> str | None:
    return dt.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def provider_info(verdict: Verdict | None) -> dict:
    """Which path produced this verdict. Never collapse these into one generic label (Stage 4 hard requirement).

    path: rule_engine | agentic | active_list | fallback. `detail` is the honest provider string, e.g.
    "rule_engine v0.1" or "rule_engine v0.1 + qwen2.5:3b-instruct (agentic, 2 tool calls)".
    """
    if verdict is None:
        return {"provider": None, "provider_detail": None, "provider_path": None, "tool_calls": 0}
    payload = verdict.payload or {}
    name = verdict.provider_name
    detail = (payload.get("provider") or {}).get("detail") or f"{name} v{verdict.provider_version}"
    trace = payload.get("agentic_trace") or []
    tool_calls = sum(1 for t in trace if t.get("type") == "tool_call")
    if verdict.fallback_from:
        path = "fallback"
    elif name.endswith("+agentic") or "(agentic" in detail:
        path = "agentic"
    elif name.startswith("active_list"):
        path = "active_list"
    else:
        path = "rule_engine"
    return {"provider": f"{name} v{verdict.provider_version}", "provider_detail": detail,
            "provider_path": path, "tool_calls": tool_calls}


def submission_row(sub: Submission) -> dict:
    verdict = current_verdict(sub)
    label = effective_label(sub) or (verdict.label if verdict else None)
    overridden = AnalystAction.objects.filter(submission=sub, kind="override").exists()
    return {
        "id": str(sub.id), "package_name": sub.package_name, "app_label": sub.app_label,
        "version_name": sub.version_name, "device": {"id": str(sub.device_id), "name": sub.device.name},
        "status": sub.status, "status_label": sub.status_label, "label": label,
        "confidence": verdict.confidence if verdict else None,
        **provider_info(verdict),
        "fallback_from": verdict.fallback_from if verdict else None,
        "overridden": overridden, "remediation_hold": sub.remediation_hold,
        "created_at": iso(sub.created_at), "updated_at": iso(sub.updated_at),
        "in_progress": sub.status in IN_PROGRESS,
    }


def submission_detail(sub: Submission) -> dict:
    verdict = current_verdict(sub)
    analysis = verdict.analysis if verdict else None
    rem = RemediationRequest.objects.filter(submission=sub).order_by("-created_at").first()
    return {
        "submission": {**submission_row(sub), "sha256": sub.sample.sha256, "size_bytes": sub.sample.size_bytes,
                       "requested_permissions": sub.requested_permissions, "installer_package": sub.installer_package,
                       "first_install_time": iso(sub.first_install_time), "error_code": sub.error_code,
                       "error_detail": sub.error_detail, "split_count": sub.split_count},
        "sample": {"sha256": sub.sample.sha256, "size_bytes": sub.sample.size_bytes,
                   "file_present": bool(sub.sample.file_path)},
        "evidence": analysis.evidence if analysis else None,
        "verdict": _verdict_out(verdict) if verdict else None,
        "verdict_history": [{"id": v.id, "label": v.label, "confidence": v.confidence, "is_current": v.is_current,
                             "provider": f"{v.provider_name} v{v.provider_version}",
                             "provider_detail": provider_info(v)["provider_detail"],
                             "provider_path": provider_info(v)["provider_path"],
                             "tool_calls": provider_info(v)["tool_calls"], "created_at": iso(v.created_at)}
                            for v in Verdict.objects.filter(submission=sub)[:20]],
        "effective_label": effective_label(sub),
        "analyst_actions": [{"kind": a.kind, "from": a.from_label, "to": a.to_label, "note": a.note,
                             "user": a.user.get_username() if a.user else None, "created_at": iso(a.created_at)}
                            for a in AnalystAction.objects.filter(submission=sub)[:50]],
        "remediation": _rem_row(rem) if rem else None,
        "remediations": [_rem_row(r) for r in RemediationRequest.objects.filter(submission=sub)[:20]],
        "rules": [_rule_out(r) for r in GeneratedRule.objects.filter(source_sha256=sub.sample.sha256)[:20]],
        "events_count": PipelineEvent.objects.filter(submission=sub).count(),
    }


def _verdict_out(v: Verdict) -> dict:
    p = v.payload
    return {
        "id": v.id, "label": v.label, "score": v.score, "confidence": v.confidence,
        "explanation": p.get("explanation", ""), "techniques": p.get("techniques", []),
        "needs_more_verification": p.get("needs_more_verification", False),
        "verification_requests": p.get("verification_requests", []),
        "recommended_action": p.get("recommended_action", "none"),
        "provider": {"name": v.provider_name, "version": v.provider_version, "fallback_from": v.fallback_from,
                     "detail": provider_info(v)["provider_detail"], "path": provider_info(v)["provider_path"]},
        "agentic_trace": p.get("agentic_trace", []),
        "generated_at": p.get("generated_at"),
    }


def _rem_row(r: RemediationRequest) -> dict:
    return {"id": str(r.id), "state": r.state, "origin": r.origin, "package_name": r.package_name,
            "created_at": iso(r.created_at), "expires_at": iso(r.expires_at), "resolved_at": iso(r.resolved_at),
            "outcome_detail": r.outcome_detail, "checks": r.policy_snapshot.get("checks", [])}


def _rule_out(r: GeneratedRule) -> dict:
    return {"id": str(r.id), "name": r.name, "kind": r.kind, "status": r.status, "version": r.version,
            "level": r.level, "fp_test": r.fp_test}


def recent_events(limit: int) -> list[dict]:
    rows = PipelineEvent.objects.select_related("submission").order_by("-id")[:limit]
    return [envelope(ev, str(ev.submission_id) if ev.submission_id else None, "pipeline.event") for ev in rows]


def events_since(sub: Submission | None, since: int, limit: int = 500) -> list[dict]:
    qs = PipelineEvent.objects.filter(id__gt=since)
    if sub is not None:
        qs = qs.filter(submission=sub)
    out = []
    for ev in qs.order_by("id")[:limit]:
        out.append(envelope(ev, str(ev.submission_id) if ev.submission_id else None, "pipeline.event"))
    return out


def device_row(d: Device) -> dict:
    return {"id": str(d.id), "name": d.name, "android_version": d.android_version, "app_version": d.app_version,
            "last_seen": iso(d.last_seen), "online": d.is_online, "protection_on": d.protection_on,
            "revoked": d.revoked, "scans": d.submissions.count(), "paired_at": iso(d.created_at)}


def stats() -> dict:
    now = timezone.now()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    by_label = {k: 0 for k in LABELS}
    recent = Verdict.objects.filter(is_current=True, created_at__gte=now - timedelta(hours=24)) \
        .select_related("submission")
    for v in recent:
        by_label[effective_label(v.submission) or v.label] = by_label.get(effective_label(v.submission) or v.label, 0) + 1
    ttv = []
    for v in Verdict.objects.filter(is_current=True).select_related("submission").order_by("-created_at")[:50]:
        ttv.append((v.created_at, (v.created_at - v.submission.created_at).total_seconds()))
    avg = round(sum(s for _, s in ttv) / len(ttv), 2) if ttv else None
    durations = sorted(sec for _, sec in ttv)
    p95 = round(durations[min(len(durations) - 1, int(len(durations) * 0.95))], 2) if durations else None
    yesterday = Submission.objects.filter(created_at__gte=midnight - timedelta(days=1), created_at__lt=midnight).count()
    return {
        "devices_total": Device.objects.filter(revoked=False).count(),
        "submissions_total": Submission.objects.count(),
        "submissions_yesterday": yesterday,
        "ttv_p95_s": p95,
        "devices_online": Device.objects.filter(revoked=False, last_seen__gte=now - timedelta(seconds=90)).count(),
        "submissions_today": Submission.objects.filter(created_at__gte=midnight).count(),
        "by_label": by_label,
        "in_progress": Submission.objects.filter(status__in=IN_PROGRESS).count(),
        "avg_time_to_verdict_s": avg,
        "pending_remediations": RemediationRequest.objects.filter(state__in=RemediationRequest.OPEN_STATES).count(),
        "ttv_series": [{"at": iso(at), "seconds": round(s, 2)} for at, s in reversed(ttv[:30])],
        "malicious_24h": by_label.get("malicious", 0),
        "generated_at": iso(now),
    }


def rule_out(rule: GeneratedRule) -> dict:
    from rules.models import RuleMatch

    techniques = (rule.verdict.payload.get("techniques", []) if rule.verdict_id else [])
    return {**_rule_row(rule),
            "hits": RuleMatch.objects.filter(rule=rule, false_positive=False).count(),
            "attck": [{"id": t.get("id"), "name": t.get("name"), "tactic": t.get("tactic", "")} for t in techniques],
            "package_name": (rule.meta or {}).get("sample_package")
            or (rule.source_submission.package_name if rule.source_submission_id else None)}


def settings_out() -> dict:
    cfg = effective_settings()
    from analysis.analyzers.reputation import _list

    return {
        "settings": {k: cfg.get(k) for k in ("auto_remediation_enabled", "auto_remediation_min_confidence",
                                             "remediation_rate_limit_per_device_hour", "protected_packages",
                                             "reasoner_backend", "dynamic_enabled", "show_demo_console")},
        "reputation_counts": {
            "bad_hashes": len(_list("bad_sha256.txt")), "good_hashes": len(_list("good_sha256.txt")),
            "bad_signers": len(_list("bad_signers.txt")),
        },
        "env": {"dynamic_available": False, "reasoner_options": ["rules", "hybrid"],
                "analysis_version": settings.SENTINEL["ANALYSIS_VERSION"]},
    }


def sample_count() -> int:
    return Sample.objects.count()
