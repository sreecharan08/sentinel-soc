"""
Deterministic first-pass rule engine. This is the honest "rule_engine v0.1"
layer -- plain if/then logic over the Stage-3 schema, nothing agentic about
it, and it should never be described as AI in the dashboard or the paper.

Severity scale is Wazuh-style 0-16 (not a 4-bucket low/med/high/critical),
so confidence scoring has room to actually mean something:
    0-3   informational   10-12 high
    4-6   low             13-15 critical
    7-9   medium          16    confirmed / emergency
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .schema import AnalysisRecord, RuleHit
from .active_lists import CorrelationWindow

SEVERITY_BANDS = {
    "informational": (0, 3),
    "low": (4, 6),
    "medium": (7, 9),
    "high": (10, 12),
    "critical": (13, 15),
    "confirmed": (16, 16),
}


@dataclass
class Rule:
    rule_id: str
    level: int
    description: str
    groups: list[str]
    attck: list[str]
    condition: Callable[[AnalysisRecord], bool]


# Signals kept consistent with the rest of the project's fixture data
# (beacon URL, excessive SMS permission, native-lib entropy 7.8, unused
# camera+mic, obfuscated ad SDK) so this plugs straight into the existing
# demo dataset without inventing a new vocabulary.
RULES: list[Rule] = [
    Rule(
        "STG4-001", 14, "Network beacon to known C2-shaped endpoint",
        groups=["network"], attck=["T1071", "TA0011"],
        condition=lambda r: len(r.network.urls) > 0 and r.has_behavior("beacon_detected"),
    ),
    Rule(
        "STG4-002", 9, "SMS permission requested without a messaging feature",
        groups=["permissions"], attck=["T1636.004", "TA0009"],
        condition=lambda r: "SEND_SMS" in r.dangerous_permissions and r.has_behavior("sms_sent_silently"),
    ),
    Rule(
        "STG4-003", 11, "Native library entropy consistent with packing/obfuscation",
        groups=["static"], attck=["T1027"],
        condition=lambda r: r.max_native_entropy() >= 7.5,
    ),
    Rule(
        "STG4-004", 7, "Camera or microphone accessed with no corresponding UI",
        groups=["dynamic", "permissions"], attck=["T1125"],
        condition=lambda r: r.has_behavior("camera_access_no_ui") or r.has_behavior("mic_access_no_ui"),
    ),
    Rule(
        "STG4-005", 8, "Obfuscated third-party SDK loaded at runtime",
        groups=["dynamic"], attck=["T1027.002"],
        condition=lambda r: r.has_behavior("obfuscated_sdk_loaded"),
    ),
    Rule(
        "STG4-006", 10, "DEX unpacked/decrypted at runtime (anti-static-analysis)",
        groups=["dynamic", "static"], attck=["T1027.007"],
        condition=lambda r: r.has_behavior("dex_unpacked_at_runtime"),
    ),
    Rule(
        "STG4-007", 12, "Contact list exfiltration attempt",
        groups=["dynamic"], attck=["T1636.003"],
        condition=lambda r: r.has_behavior("contacts_exfil_attempt"),
    ),
    Rule(
        "STG4-008", 6, "Self-signed certificate with no issuer metadata",
        groups=["static"], attck=["T1587.002"],
        condition=lambda r: r.cert.is_self_signed and not r.cert.issuer,
    ),
    Rule(
        "STG4-009", 13, "Accessibility service used for input capture/abuse",
        groups=["dynamic", "permissions"], attck=["T1056.004"],
        condition=lambda r: r.has_behavior("accessibility_service_abuse"),
    ),
]


def evaluate(record: AnalysisRecord, correlation: CorrelationWindow | None = None) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rule in RULES:
        if rule.condition(record):
            hits.append(RuleHit(rule.rule_id, rule.level, rule.description, rule.groups, rule.attck))

    if correlation is not None:
        for hit in hits:
            correlation.record(record.device_id, hit.level)
        # Wazuh-style frequency escalation: 3+ medium-or-worse hits on the
        # same device inside the window is a different, worse signal than
        # any single hit -- even if none of them alone reached "high".
        repeat_count = correlation.count_since(record.device_id, min_level=7)
        if repeat_count >= 3:
            hits.append(RuleHit(
                "STG4-COR-01", 13,
                f"{repeat_count} medium+ findings on this device within the correlation window",
                groups=["correlation"], attck=["TA0003"],
            ))

    return hits


def aggregate_confidence(hits: list[RuleHit]) -> tuple[str, float]:
    """Deterministic mapping from rule hits to (verdict_bucket, confidence).
    This is the number the LLM loop is allowed to override downward (ask
    for more evidence) but never silently upward without a tool call that
    justifies it -- see agent.py."""
    if not hits:
        return "benign", 0.9
    top = max(h.level for h in hits)
    total = min(sum(h.level for h in hits), 48)  # cap so one device's long tail doesn't blow past 1.0
    confidence = round(total / 48, 2)
    if top >= 13 or confidence >= 0.75:
        return "malicious", max(confidence, 0.75)
    if top >= 7 or confidence >= 0.35:
        return "suspicious", confidence
    return "unknown", confidence
