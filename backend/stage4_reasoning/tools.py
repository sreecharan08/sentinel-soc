"""
The real actions the agent is allowed to take. Each one is a genuine call
back into the rest of your pipeline -- this is what makes the loop actually
agentic rather than a single LLM call dressed up as one: the model decides
*whether* to call these and *which*, and each call changes what it sees next.

Wired to the Stage 2/3 data in this repo (stored Analysis evidence and
verdict history). Dynamic re-tracing is reported as unavailable because the
emulator runner is not installed. The signatures and the agent loop around
them are unchanged.
"""

from __future__ import annotations

from .schema import AnalysisRecord


def _latest_evidence(sha256: str) -> dict | None:
    """Stored Stage-3 evidence for this sample, or None outside the Django app (demo.py, unit tests)."""
    try:
        from analysis.models import Analysis

        row = Analysis.objects.filter(sample__sha256=sha256).order_by("-analysis_version", "-id").first()
        return row.evidence if row else None
    except Exception:  # noqa: BLE001 - no Django / no database: tools degrade to what the record already holds
        return None


def request_dynamic_trace(record: AnalysisRecord, focus: str) -> dict:
    """Dynamic analysis is not installed in this build (DYNAMIC_ENABLED=false, no emulator runner), so a
    focused re-trace cannot be dispatched. Say so plainly instead of fabricating a trace; the agent gets
    whatever behaviours Stage 3 already recorded and can decide to conclude on that."""
    return {
        "focus": focus,
        "available": False,
        "note": "dynamic analysis is not available in this deployment; no new trace was collected",
        "observed": record.dynamic_behaviors,
    }


def request_similar_samples(record: AnalysisRecord, ioc: str) -> dict:
    """Other samples in submission history whose static strings reference this IOC, with their current verdicts."""
    try:
        import json

        from analysis.models import Analysis
        from submissions.models import Verdict

        matches = []
        seen: set[str] = set()
        for row in Analysis.objects.select_related("sample").order_by("-id")[:500]:
            sha = row.sample.sha256
            if sha == record.sha256 or sha in seen:
                continue
            strings = row.evidence.get("static", {}).get("strings", {})
            if ioc not in json.dumps(strings):
                continue
            seen.add(sha)
            verdict = (Verdict.objects.filter(submission__sample=row.sample, is_current=True)
                       .order_by("-created_at").first())
            matches.append({"sha256": sha, "verdict": verdict.label if verdict else "unknown"})
            if len(matches) >= 10:
                break
        return {"ioc": ioc, "matches": matches}
    except Exception as exc:  # noqa: BLE001
        return {"ioc": ioc, "matches": [], "note": f"history lookup unavailable: {exc}"}


def request_manifest_detail(record: AnalysisRecord) -> dict:
    """Manifest context beyond the permission list: components, exported surface, accessibility/admin services."""
    detail: dict = {"declared": record.permissions, "flagged_dangerous": record.dangerous_permissions}
    manifest = (_latest_evidence(record.sha256) or {}).get("static", {}).get("manifest", {})
    if manifest:
        components = manifest.get("components", {})
        detail.update({
            "has_launcher_activity": manifest.get("has_launcher_activity"),
            "debuggable": manifest.get("debuggable"),
            "target_sdk": manifest.get("target_sdk"),
            "component_counts": {k: len(v) for k, v in components.items() if isinstance(v, list)},
            "exported_unguarded": sum(1 for c in manifest.get("exported_components", []) if not c.get("permission")),
            "accessibility_services": manifest.get("accessibility_services", []),
            "device_admin_receivers": manifest.get("device_admin_receivers", []),
        })
    return detail


TOOLS = {
    "request_dynamic_trace": request_dynamic_trace,
    "request_similar_samples": request_similar_samples,
    "request_manifest_detail": request_manifest_detail,
}
