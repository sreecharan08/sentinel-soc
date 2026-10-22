"""Stage 4 hybrid reasoner: evidence -> AnalysisRecord -> verdict, validated against verdict.schema.json."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import reasoning.hybrid_reasoner as hybrid
from reasoning.interface import ReasonContext
from reasoning.registry import get_reasoner
from stage4_reasoning.active_lists import CorrelationWindow, JSONActiveLists

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "shared" / "verdict.schema.json").read_text())
SHA = "ab" * 32


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    for var in ("STAGE4_LLM_BASE_URL", "STAGE4_LLM_API_KEY", "STAGE4_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)          # force the deterministic mock LLM
    monkeypatch.setattr(hybrid, "_active_lists", JSONActiveLists(tmp_path / "lists.json"))
    monkeypatch.setattr(hybrid, "_correlation", CorrelationWindow())


def _evidence(signals, **static):
    return {"schema_version": "1.0", "sample_sha256": SHA, "analysis_version": 4,
            "static": {"manifest": {"package": "com.example.app", "permissions": [], "dangerous_permissions": []},
                       "signing": {}, "strings": {}, "native": {}, **static},
            "dynamic": None, "reputation": {}, "signals": signals, "partial": False, "partial_reasons": []}


def _sig(n, code, severity="high", attck=()):
    return {"id": f"sig_{n}", "code": code, "name": code, "severity": severity, "category": "x",
            "source": "code", "detail": "d", "attck": list(attck)}


def _ctx():
    return ReasonContext(submission_id="sub-1", device_info={"device_id": "dev-1"})


def test_registry_resolves_hybrid():
    assert get_reasoner("hybrid").name == "hybrid"


def test_benign_when_nothing_fires_and_verdict_matches_schema():
    v = get_reasoner("hybrid").reason(_evidence([]), _ctx())
    Draft202012Validator(SCHEMA).validate(v)
    assert v["label"] == "benign" and v["provider"]["name"] == "rule_engine"


def test_static_capability_signals_become_rule_hits_with_real_evidence_ids():
    ev = _evidence(
        [_sig(1, "SIG-CODE-009", attck=("T1417",)), _sig(2, "SIG-CODE-004")],
        manifest={"package": "com.example.app", "permissions": ["android.permission.SEND_SMS"],
                  "dangerous_permissions": ["android.permission.SEND_SMS"]})
    v = get_reasoner("hybrid").reason(ev, _ctx())
    Draft202012Validator(SCHEMA).validate(v)
    # accessibility abuse (13) is "malicious" at the 0.75 floor, which is inside the borderline band, so the
    # agentic loop decides; the deterministic mock LLM concludes "suspicious".
    assert v["provider"]["name"] == "rule_engine+agentic"
    assert v["label"] == "suspicious" and v["recommended_action"] == "monitor"
    cited = {i for t in v["techniques"] for i in t["evidence_ids"]}
    assert cited <= {"sig_1", "sig_2"}                              # never cites an id that is not in the evidence
    assert all(t["id"].startswith("T") for t in v["techniques"])     # tactic ids (TA....) are not techniques


def test_to_record_derives_behaviour_tags_only_from_matching_static_signals():
    ev = _evidence([_sig(1, "SIG-CODE-009"), _sig(2, "SIG-CODE-004")],
                   manifest={"package": "p", "permissions": ["android.permission.SEND_SMS"],
                             "dangerous_permissions": ["android.permission.SEND_SMS"]})
    record, tags = hybrid.to_record(ev, _ctx())
    assert record.dynamic_behaviors == ["accessibility_service_abuse", "sms_sent_silently"]
    assert tags["sms_sent_silently"] == ["sig_2"] and record.dangerous_permissions == ["SEND_SMS"]
    assert hybrid.to_record(_evidence([_sig(2, "SIG-CODE-004")]), _ctx())[0].dynamic_behaviors == []  # no SEND_SMS


def test_never_less_severe_than_stage2_rule_engine_baseline():
    # SIG-PERM-001 (SMS access, high) + SIG-PERM-003 (accessibility, high) make the Stage 2 engine say malicious/suspicious,
    # while no Stage 4 behaviour tag is derivable from them.
    ev = _evidence([_sig(1, "SIG-PERM-001", "high"), _sig(2, "SIG-PERM-003", "high"), _sig(3, "SIG-CODE-001", "medium")])
    v = get_reasoner("hybrid").reason(ev, _ctx())
    Draft202012Validator(SCHEMA).validate(v)
    assert v["label"] in ("suspicious", "malicious")
    assert v["provider"]["name"] == "rule_engine" and "baseline" in v["provider"]["detail"]


def test_repeat_sample_short_circuits_via_active_list():
    ev = _evidence([_sig(1, "SIG-CODE-009")])
    first = get_reasoner("hybrid").reason(ev, _ctx())
    second = get_reasoner("hybrid").reason(ev, _ctx())
    assert first["label"] == second["label"] == "suspicious"
    assert second["provider"]["name"] == "active_list_match"


def test_borderline_case_runs_agentic_loop_with_tool_calls():
    # beacon_detected (14) + camera_access_no_ui (7) = 0.75 confidence: inside the borderline band
    ev = _evidence([], manifest={"package": "com.example.app", "permissions": [], "dangerous_permissions": []})
    ev["dynamic"] = {"behaviors": ["beacon_detected", "camera_access_no_ui"]}
    ev["static"]["strings"] = {"urls": ["http://185.220.101.9/beacon"]}
    v = get_reasoner("hybrid").reason(ev, _ctx())
    Draft202012Validator(SCHEMA).validate(v)
    assert v["provider"]["name"] == "rule_engine+agentic"
    assert any(t["type"] == "tool_call" for t in v["agentic_trace"])
