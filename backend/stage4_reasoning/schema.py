"""
Stage 3 -> Stage 4 field contract.

This is the normalized shape that Stage 3 (static/dynamic analysis) must
hand to Stage 4 (reasoning). Keeping this as one explicit schema is the
"decoder" half of the Wazuh-style split: Stage 3's job is to produce exactly
this shape no matter what CAPE/Ghidra/Frida output looked like internally.
Stage 4's rule engine and LLM loop never touch raw sandbox output directly --
only these fields. That keeps Stage 4 swappable (rule-only, LLM-only, hybrid)
without touching Stage 3.

Nothing here talks to a network or a model. Pure data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class NetworkIOCs:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


@dataclass
class NativeLib:
    name: str
    entropy: float  # 0-8, Shannon entropy of the .so; >7.5 is suspicious-packed territory


@dataclass
class CertInfo:
    is_self_signed: bool = False
    issuer: str | None = None
    valid_from: str | None = None


@dataclass
class AnalysisRecord:
    """One Stage-3 output: everything Stage 4 is allowed to know about a sample."""

    sample_id: str
    package_name: str
    sha256: str
    device_id: str

    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)  # subset flagged dangerous by manifest analysis

    native_libs: list[NativeLib] = field(default_factory=list)
    string_iocs: list[str] = field(default_factory=list)  # raw suspicious strings pulled from static pass
    network: NetworkIOCs = field(default_factory=NetworkIOCs)

    dynamic_behaviors: list[str] = field(default_factory=list)
    # free-form behavior tags Stage 3 is expected to normalize to, e.g.:
    #   "beacon_detected", "sms_sent_silently", "camera_access_no_ui",
    #   "mic_access_no_ui", "obfuscated_sdk_loaded", "dex_unpacked_at_runtime",
    #   "contacts_exfil_attempt", "accessibility_service_abuse"

    cert: CertInfo = field(default_factory=CertInfo)

    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def has_behavior(self, tag: str) -> bool:
        return tag in self.dynamic_behaviors

    def max_native_entropy(self) -> float:
        return max((lib.entropy for lib in self.native_libs), default=0.0)


@dataclass
class RuleHit:
    rule_id: str
    level: int  # 0-16, Wazuh-style severity scale (see rules.py SEVERITY_BANDS)
    description: str
    groups: list[str]
    attck: list[str]


@dataclass
class Stage4Verdict:
    sample_id: str
    verdict: str  # "malicious" | "suspicious" | "benign" | "unknown"
    confidence: float  # 0.0-1.0
    attck: list[str]
    rationale: str
    rule_hits: list[RuleHit]
    provider: str  # honest label of what produced this verdict, e.g.
    # "rule_engine v0.1" or "rule_engine v0.1 + qwen-turbo (agentic, 3 tool calls)"
    agentic_trace: list[dict] = field(default_factory=list)  # tool-call log, empty if rule-only
