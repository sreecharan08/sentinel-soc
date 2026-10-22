"""Stage 4 Reasoner (REASONER_BACKEND=hybrid): deterministic rule engine + active lists, with the agentic
LLM loop only for borderline cases. Adapts the Stage 3 evidence dict to stage4_reasoning's AnalysisRecord and
the Stage4Verdict back to the Verdict contract. The reasoning logic itself lives in stage4_reasoning/.

provider.name is honest about which path ran: "rule_engine", "active_list_match" or "rule_engine+agentic".
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

from django.conf import settings

from stage4_reasoning.active_lists import CorrelationWindow, JSONActiveLists
from stage4_reasoning.agent import analyze
from stage4_reasoning.llm_client import LLMClient
from stage4_reasoning.schema import AnalysisRecord, CertInfo, NativeLib, NetworkIOCs

from .interface import ReasonContext
from .rule_reasoner import RuleReasoner

SEVERITY_RANK = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
TECHNIQUES = {   # names for the technique ids the Stage 4 rules emit; unknown ids fall back to the id itself
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1636": ("Protected User Data", "collection"),
    "T1636.003": ("Protected User Data: Contact List", "collection"),
    "T1636.004": ("Protected User Data: SMS Messages", "collection"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "defense-evasion"),
    "T1027.007": ("Obfuscated Files or Information: Dynamic API Resolution", "defense-evasion"),
    "T1125": ("Video Capture", "collection"),
    "T1056.004": ("Input Capture: Credential API Hooking", "credential-access"),
    "T1587.002": ("Develop Capabilities: Code Signing Certificates", "resource-development"),
}
ACTION = {"malicious": "uninstall", "suspicious": "monitor", "benign": "none", "unknown": "none"}

_active_lists: JSONActiveLists | None = None
_correlation = CorrelationWindow()


def _lists() -> JSONActiveLists:
    global _active_lists
    if _active_lists is None:
        path = settings.SENTINEL["DATA_DIR"] / "stage4_active_lists.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        _active_lists = JSONActiveLists(path=path)
    return _active_lists


def _short(perm: str) -> str:
    return perm.rsplit(".", 1)[-1]


def to_record(evidence: dict[str, Any], ctx: ReasonContext) -> tuple[AnalysisRecord, dict[str, list[str]]]:
    """Returns the record plus {behaviour tag: [signal ids]} so verdict techniques can cite real evidence ids."""
    static = evidence.get("static", {}) or {}
    manifest = static.get("manifest", {}) or {}
    signing = static.get("signing", {}) or {}
    strings = static.get("strings", {}) or {}
    signals = evidence.get("signals", []) or []
    by_code: dict[str, list[str]] = {}
    for s in signals:
        by_code.setdefault(s["code"], []).append(s["id"])

    # Behaviour tags. Real dynamic output (none in this build) is used as-is. Where static analysis directly
    # shows the same capability, the matching tag is derived from signals; nothing is invented otherwise.
    tags: dict[str, list[str]] = {}
    dynamic = evidence.get("dynamic") or {}
    for tag in dynamic.get("behaviors", []) if isinstance(dynamic, dict) else []:
        tags.setdefault(tag, [])
    perms = {_short(p) for p in manifest.get("permissions", [])}
    if "SIG-CODE-009" in by_code:
        tags.setdefault("accessibility_service_abuse", []).extend(by_code["SIG-CODE-009"])
    if "SIG-CODE-004" in by_code and "SEND_SMS" in perms:
        tags.setdefault("sms_sent_silently", []).extend(by_code["SIG-CODE-004"])
    if "SIG-CODE-001" in by_code and "SIG-FILE-001" in by_code:
        tags.setdefault("dex_unpacked_at_runtime", []).extend(by_code["SIG-CODE-001"] + by_code["SIG-FILE-001"])

    urls = list(strings.get("urls", []))
    cert_issuer = (signing.get("certs") or [{}])[0].get("issuer") if signing.get("certs") else None
    record = AnalysisRecord(
        sample_id=ctx.submission_id,
        package_name=manifest.get("package", "") or "",
        sha256=evidence.get("sample_sha256", ""),
        device_id=str(ctx.device_info.get("device_id") or ctx.device_info.get("id") or "unknown"),
        permissions=sorted(perms),
        dangerous_permissions=sorted(_short(p) for p in manifest.get("dangerous_permissions", [])),
        native_libs=[NativeLib(lib.get("name", "?"), float(lib["entropy"]))   # Stage 3 does not emit lib entropy yet
                     for lib in (static.get("native") or {}).get("libs", []) if "entropy" in lib],
        string_iocs=urls,
        network=NetworkIOCs(urls=urls, ips=list(strings.get("ips", [])),
                            domains=list((strings.get("flagged_hosts") or {}).keys())),
        dynamic_behaviors=sorted(tags),
        cert=CertInfo(is_self_signed=bool(signing.get("self_signed")), issuer=cert_issuer),
    )
    return record, tags


class HybridReasoner:
    name = "hybrid"
    version = "0.1"

    def reason(self, evidence: dict[str, Any], ctx: ReasonContext) -> dict[str, Any]:
        try:
            return self._reason(evidence, ctx)
        except Exception as exc:  # contract: never raise
            return self._verdict(evidence, ctx, "unknown", 0.0, 0.0, [], f"Hybrid reasoner failed: {exc}",
                                 provider="hybrid")

    def _reason(self, evidence, ctx):
        # Stage 4's rules key on behaviour tags that static analysis rarely produces, so on static-only evidence it can
        # score a sample lower than the Stage 2 rule engine does. Never go below that baseline: the stage 2 verdict
        # stands (and says so) whenever Stage 4 would be less severe.
        baseline = RuleReasoner().reason(evidence, ctx)
        record, tags = to_record(evidence, ctx)
        result = analyze(record, _lists(), _correlation, LLMClient())
        if SEVERITY_RANK.get(result.verdict, 0) < SEVERITY_RANK.get(baseline["label"], 0):
            baseline["explanation"] = ("Stage 2 rule engine baseline kept: the Stage 4 reasoner found "
                                       f"{result.verdict} but static signals alone rate this {baseline['label']}. "
                                       + baseline["explanation"])
            baseline["provider"]["detail"] = "rule_engine v0.1 (static baseline; Stage 4 was less severe)"
            return baseline

        # provider string is "rule_engine v0.1", "active_list_match v0.1" or "rule_engine v0.1 + <model> (agentic, N tool calls)"
        if result.provider.startswith("active_list_match"):
            provider = "active_list_match"
        elif "(agentic" in result.provider:
            provider = "rule_engine+agentic"
        else:
            provider = "rule_engine"

        known = {s["id"] for s in evidence.get("signals", [])}
        rule_tags = {"STG4-001": "beacon_detected", "STG4-002": "sms_sent_silently", "STG4-004": "camera_access_no_ui",
                     "STG4-005": "obfuscated_sdk_loaded", "STG4-006": "dex_unpacked_at_runtime",
                     "STG4-007": "contacts_exfil_attempt", "STG4-009": "accessibility_service_abuse"}
        rule_evidence: dict[str, set[str]] = {}
        for hit in result.rule_hits:
            ids = {i for i in tags.get(rule_tags.get(hit.rule_id, ""), []) if i in known}
            for tid in hit.attck:
                rule_evidence.setdefault(tid, set()).update(ids)

        techniques = []
        for tid in result.attck:
            if not TECHNIQUE_ID.match(tid):   # tactic ids (TA....) and anything malformed from the model are dropped
                continue
            name, tactic = TECHNIQUES.get(tid, (tid, ""))
            techniques.append({"id": tid, "name": name, "tactic": tactic,
                               "confidence": round(min(0.9, result.confidence), 2),
                               "evidence_ids": sorted(rule_evidence.get(tid, set()))})

        score = min(1.0, sum(h.level for h in result.rule_hits) / 48)
        if provider == "active_list_match":
            score = result.confidence
        trace = [t for t in result.agentic_trace]
        explanation = result.rationale
        if trace:
            calls = [t for t in trace if t.get("type") == "tool_call"]
            if calls:
                explanation += " Checks run: " + ", ".join(f"{t['tool']}" for t in calls) + "."
        verdict = self._verdict(evidence, ctx, result.verdict, score, result.confidence, techniques,
                                explanation, provider=provider)
        verdict["agentic_trace"] = trace            # extra key; the schema does not forbid additional properties
        verdict["provider"]["detail"] = result.provider
        return verdict

    def _verdict(self, evidence, ctx, label, score, confidence, techniques, explanation, provider):
        return {
            "schema_version": "1.0",
            "submission_id": ctx.submission_id,
            "sample_sha256": evidence.get("sample_sha256", "0" * 64),
            "label": label,
            "score": round(max(0.0, min(1.0, score)), 2),
            "confidence": round(max(0.0, min(1.0, confidence)), 2),
            "techniques": techniques,
            "explanation": explanation,
            "needs_more_verification": False,
            "verification_requests": [],
            "recommended_action": ACTION.get(label, "none"),
            "provider": {"name": provider, "version": self.version, "fallback_from": None},
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
