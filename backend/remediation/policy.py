"""Remediation guardrails (Stage 6 section 2.4). Pure: no database access, so every check is unit-testable.

Run the self-check with:  python -m pytest remediation/tests  (see tests T6-01..T6-05)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

BUILTIN_PROTECTED_PREFIXES = ("com.android.",)
BUILTIN_PROTECTED_EXACT = {"android", "com.google.android.gms"}


@dataclass
class Check:
    id: str
    passed: bool
    detail: str


@dataclass
class PolicyDecision:
    allowed: bool
    checks: list[Check] = field(default_factory=list)

    def as_snapshot(self) -> dict:
        return {"allowed": self.allowed, "checks": [{"id": c.id, "passed": c.passed, "detail": c.detail}
                                                    for c in self.checks]}


def is_protected(package: str, extra: set[str], own_package: str) -> bool:
    return (package in BUILTIN_PROTECTED_EXACT or package == own_package or package in extra
            or package.startswith(BUILTIN_PROTECTED_PREFIXES))


def evaluate(origin: str, *, package: str, label: str, confidence: float, recommended_action: str,
             settings: dict, hold: bool, device_last_seen: datetime | None, device_revoked: bool,
             open_request_exists: bool, recent_declined: bool, recent_count: int,
             protected: set[str], own_package: str = "com.sentinel.soc",
             now: datetime | None = None) -> PolicyDecision:
    now = now or datetime.now(timezone.utc)
    min_conf = float(settings.get("auto_remediation_min_confidence", 0.85))
    rate_limit = int(settings.get("remediation_rate_limit_per_device_hour", 3))
    enabled = bool(settings.get("auto_remediation_enabled", False))
    protected_now = is_protected(package, protected, own_package)
    active = (not device_revoked and device_last_seen is not None
              and now - device_last_seen <= timedelta(minutes=5))

    checks = [
        Check("enabled", enabled, "Automatic remediation is " + ("on" if enabled else "off")),
        Check("label_malicious", label == "malicious", f"Effective label is {label}"),
        Check("confidence", confidence >= min_conf, f"Confidence {confidence:.0%} vs minimum {min_conf:.0%}"),
        Check("recommended", recommended_action == "uninstall", f"Recommended action is {recommended_action}"),
        Check("no_hold", not hold, "Analyst hold is " + ("set" if hold else "not set")),
        Check("not_protected", not protected_now, f"{package} is " + ("protected" if protected_now else "not protected")),
        Check("no_open_request", not open_request_exists and not recent_declined,
              "An open request exists" if open_request_exists else
              ("The user declined within the last 24 h" if recent_declined else "No open or recently declined request")),
        Check("rate_limit", recent_count < rate_limit, f"{recent_count} requests this hour (limit {rate_limit})"),
        Check("device_active", active, "Device recently active" if active else "Device revoked or not seen in 5 min"),
    ]
    by_id = {c.id: c for c in checks}
    if origin == "auto":
        required = [c.passed for c in checks]
    else:  # analyst: judgment replaces the label/confidence gates; safety gates still apply
        required = [by_id[k].passed for k in ("not_protected", "no_open_request", "device_active")]
    return PolicyDecision(allowed=all(required), checks=checks)
