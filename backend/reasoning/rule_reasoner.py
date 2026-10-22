"""Placeholder Reasoner (provider name: rule_engine). Deterministic, explainable, no model.

It is the default until Stage 4 is decided and the fallback if any other reasoner fails.
Tune weights in one place (SEVERITY_WEIGHT).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .interface import ReasonContext

SEVERITY_WEIGHT = {"info": 0.0, "low": 0.05, "medium": 0.15, "high": 0.30, "critical": 0.50}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
BAD_SCORE, SUSPICIOUS_SCORE = 0.70, 0.30

ATTCK_NAMES = {   # verify against the current ATT&CK for Mobile matrix before presenting
    "T1636": ("Protected User Data", "collection"),
    "T1417": ("Input Capture", "collection"),
    "T1407": ("Download New Code at Runtime", "defense-evasion"),
    "T1406": ("Obfuscated Files or Information", "defense-evasion"),
    "T1430": ("Location Tracking", "collection"),
    "T1655": ("Masquerading", "defense-evasion"),
    "T1418": ("Software Discovery", "discovery"),
}


class RuleReasoner:
    name = "rule_engine"
    version = "0.1"

    def reason(self, evidence: dict[str, Any], ctx: ReasonContext) -> dict[str, Any]:
        try:
            return self._reason(evidence, ctx)
        except Exception as exc:  # contract: never raise
            return self._verdict(evidence, ctx, "unknown", 0.0, 0.0, [], f"Rule engine failed: {exc}")

    def _reason(self, evidence, ctx):
        signals = evidence.get("signals", [])
        rep = evidence.get("reputation", {})
        # Each signal code counts once, at its highest severity. Repeats (20 blobs, 5 URLs) are one finding.
        worst: dict[str, dict] = {}
        for s in signals:
            if s["code"] not in worst or SEVERITY_ORDER.index(s["severity"]) < SEVERITY_ORDER.index(worst[s["code"]]["severity"]):
                worst[s["code"]] = s
        score = min(1.0, sum(SEVERITY_WEIGHT.get(s["severity"], 0.0) for s in worst.values()))
        has_strong = any(s["severity"] in ("high", "critical") for s in worst.values())
        if rep.get("bad_hash_hit"):
            score = 1.0
        elif rep.get("good_hash_hit"):
            score *= 0.2

        # Malicious needs a strong, specific signal as well as a high score. Library noise alone reaches "suspicious".
        if score >= BAD_SCORE and (has_strong or rep.get("bad_hash_hit")):
            label, action = "malicious", "uninstall"
        elif score >= BAD_SCORE:
            label, action = "suspicious", "monitor"
        elif score >= SUSPICIOUS_SCORE:
            label, action = "suspicious", "monitor"
        else:
            label, action = "benign", "none"

        meaningful = [s for s in signals if s["severity"] != "info"]
        if label == "benign":
            confidence = round(min(0.9, 0.6 + (SUSPICIOUS_SCORE - score)), 2)
        else:
            confidence = round(min(0.95, 0.5 + 0.08 * len(meaningful)), 2)

        top = sorted(signals, key=lambda s: SEVERITY_ORDER.index(s["severity"]))[:3]
        if top:
            explanation = (f"Risk score {score:.2f} from {len(meaningful)} notable signals. "
                           + "Key findings: " + "; ".join(f"{s['name']} ({s['severity']})" for s in top) + ".")
        else:
            explanation = "No notable risk signals were found."

        techniques: dict[str, dict] = {}
        for s in signals:
            for tid in s.get("attck", []):
                t = techniques.setdefault(tid, {"id": tid, "name": ATTCK_NAMES.get(tid, (tid, ""))[0],
                                                "tactic": ATTCK_NAMES.get(tid, ("", ""))[1],
                                                "confidence": 0.0, "evidence_ids": []})
                t["evidence_ids"].append(s["id"])
                t["confidence"] = round(min(0.9, t["confidence"] + 0.3), 2)

        verdict = self._verdict(evidence, ctx, label, score, confidence, list(techniques.values()),
                                explanation, action)
        if ctx.dynamic_allowed and evidence.get("dynamic") is None and SUSPICIOUS_SCORE <= score < BAD_SCORE:
            verdict["needs_more_verification"] = True
            verdict["verification_requests"] = [
                {"kind": "dynamic", "reason": "Borderline static score; confirm runtime behaviour",
                 "focus": ["network", "permissions"]}]
        return verdict

    def _verdict(self, evidence, ctx, label, score, confidence, techniques, explanation, action="none"):
        return {
            "schema_version": "1.0",
            "submission_id": ctx.submission_id,
            "sample_sha256": evidence.get("sample_sha256", "0" * 64),
            "label": label,
            "score": round(score, 2),
            "confidence": confidence,
            "techniques": techniques,
            "explanation": explanation,
            "needs_more_verification": False,
            "verification_requests": [],
            "recommended_action": action,
            "provider": {"name": self.name, "version": self.version, "fallback_from": None},
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
