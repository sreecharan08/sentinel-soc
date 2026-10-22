"""Demo pre-flight (Stage 7 section 10). Overall: ready (all pass), warn (some warnings), not_ready (any fail)."""
from __future__ import annotations

import shutil
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from devices.models import Device
from rules.models import GeneratedRule
from submissions.models import Submission


def run_preflight() -> dict:
    from dashboard.settings_store import effective_settings
    from pipeline.health import health_report

    cfg = effective_settings()
    health = health_report()
    checks = []

    def add(cid, label, status, detail):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail})

    add("server", "Server reachable", "pass", "Responding to requests")
    add("db", "Database", "pass" if health["db"] else "fail", "Connected" if health["db"] else "Unavailable")
    if health["redis"] is None:
        add("redis", "Redis", "warn", "Not configured: in-process queue and channels (dev only)")
    else:
        add("redis", "Redis", "pass" if health["redis"] else "fail", "Reachable" if health["redis"] else "Unreachable")
    add("workers", "Analysis workers", "pass" if health["workers"] >= 1 else "fail",
        f"{health['workers']} online")
    online = Device.objects.filter(revoked=False, last_seen__gte=timezone.now() - timedelta(seconds=90)).count()
    add("devices", "Phone online (seen in 90 s)", "pass" if online >= 1 else "warn", f"{online} online")
    versions = sorted({d.app_version for d in Device.objects.exclude(app_version="")})
    add("app_version", "Phone app version", "pass" if versions else "warn",
        ", ".join(versions) if versions else "No phone has reported a version yet")
    add("reasoner", "Reasoner", "pass", f"{cfg['reasoner_backend']} (rule_engine v0.1)")
    add("dynamic", "Dynamic analysis", "pass" if not cfg["dynamic_enabled"] else "warn",
        "Off" if not cfg["dynamic_enabled"] else "On (not installed in this build)")
    add("auto_remediation", "Auto-remediation", "pass" if not cfg["auto_remediation_enabled"] else "warn",
        "Off (analyst-driven)" if not cfg["auto_remediation_enabled"] else "On: confirm before the demo")
    active_rules = GeneratedRule.objects.filter(status="approved").count()
    add("rules", "Active rules", "pass", f"{active_rules} approved")
    count = Submission.objects.count()
    add("demo_data", "Demo data clean", "pass" if count == 0 else "warn",
        "Clean" if count == 0 else f"{count} submissions present: run reset before the demo")
    free_gb = shutil.disk_usage(settings.SENTINEL["DATA_DIR"]).free / (1024 ** 3)
    add("disk", "Free disk (>= 10 GB)", "pass" if free_gb >= 10 else "warn", f"{free_gb:.1f} GB free")
    fault = cfg.get("fault")
    add("fault", "Fault injection", "pass" if not fault else "fail",
        "None active" if not fault else f"Active: {fault}")

    statuses = {c["status"] for c in checks}
    overall = "not_ready" if "fail" in statuses else ("warn" if "warn" in statuses else "ready")
    return {"overall": overall, "checks": checks}
