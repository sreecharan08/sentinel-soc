"""Pure unit tests: guardrails (Stage 6 T6-01..05), Sigma evaluator (T6-13), signal catalog (Stage 3),
and archive safety (Stage 3 T3-03/T3-04/T3-05). No database needed."""
import io
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from analysis.safe_zip import open_safely
from analysis.signals import build_signals
from remediation.policy import evaluate
from rules import sigma

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _base(**over):
    kw = dict(package="com.demo.expfixture", label="malicious", confidence=0.9, recommended_action="uninstall",
              settings={"auto_remediation_enabled": True, "auto_remediation_min_confidence": 0.85,
                        "remediation_rate_limit_per_device_hour": 3},
              hold=False, device_last_seen=NOW - timedelta(seconds=20), device_revoked=False,
              open_request_exists=False, recent_declined=False, recent_count=0, protected=set(), now=NOW)
    kw.update(over)
    return kw


def test_t6_01_all_checks_pass_and_nine_checks_are_stored():
    d = evaluate("auto", **_base())
    assert d.allowed is True
    assert len(d.checks) == 9
    assert all(c.passed for c in d.checks)


def test_t6_02_confidence_just_below_threshold_blocks():
    d = evaluate("auto", **_base(confidence=0.84))
    assert d.allowed is False
    assert {c.id for c in d.checks if not c.passed} == {"confidence"}


def test_t6_03_analyst_override_to_benign_blocks_auto():
    d = evaluate("auto", **_base(label="benign"))
    assert d.allowed is False
    assert "label_malicious" in {c.id for c in d.checks if not c.passed}


def test_t6_04_protected_package_blocked_for_both_origins():
    for origin in ("auto", "analyst"):
        d = evaluate(origin, **_base(package="com.android.chrome"))
        assert d.allowed is False
        assert "not_protected" in {c.id for c in d.checks if not c.passed}


def test_t6_05_fourth_request_in_an_hour_is_rate_limited():
    d = evaluate("auto", **_base(recent_count=3))
    assert d.allowed is False
    assert "rate_limit" in {c.id for c in d.checks if not c.passed}


def test_auto_off_is_the_default_kill_switch():
    d = evaluate("auto", **_base(settings={"auto_remediation_enabled": False}))
    assert d.allowed is False


def test_analyst_origin_ignores_label_and_confidence_gates():
    d = evaluate("analyst", **_base(label="suspicious", confidence=0.4, settings={"auto_remediation_enabled": False}))
    assert d.allowed is True


def test_sigma_evaluator_matches_metadata_and_rejects_benign():
    rule = sigma.load(
        "title: t\nid: 1\nlogsource: {product: sentinel_soc, service: android_install}\n"
        "detection:\n  selection:\n    requested_permissions|all:\n      - android.permission.READ_SMS\n"
        "      - android.permission.INTERNET\n  filter_store:\n    installer_package: com.android.vending\n"
        "  condition: selection and not filter_store\nlevel: medium\n")
    risky = {"requested_permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
             "installer_package": ""}
    store = {"requested_permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
             "installer_package": "com.android.vending"}
    benign = {"requested_permissions": ["android.permission.INTERNET"], "installer_package": ""}
    assert sigma.evaluate(rule, risky) is True
    assert sigma.evaluate(rule, store) is False
    assert sigma.evaluate(rule, benign) is False


def test_sigma_hash_rule_matches_exact_hash_only():
    rule = sigma.load(
        "title: h\nid: 2\nlogsource: {product: sentinel_soc, service: android_install}\n"
        "detection:\n  selection:\n    apk_sha256: " + "a" * 64 + "\n  condition: selection\nlevel: high\n")
    assert sigma.evaluate(rule, {"apk_sha256": "a" * 64}) is True
    assert sigma.evaluate(rule, {"apk_sha256": "b" * 64}) is False


def test_sigma_rejects_unsupported_syntax():
    with pytest.raises(sigma.UnsupportedSigma):
        sigma.load("title: x\nid: 3\nlogsource: {product: sentinel_soc, service: android_install}\n"
                   "detection:\n  selection:\n    apk_sha256|re: '.*'\n  condition: selection\nlevel: low\n")


def test_sigma_rejects_wrong_logsource():
    with pytest.raises(sigma.UnsupportedSigma):
        sigma.load("title: x\nid: 4\nlogsource: {product: windows}\n"
                   "detection:\n  selection:\n    apk_sha256: x\n  condition: selection\nlevel: low\n")


def test_signal_catalog_fires_expected_codes_and_orders_stably():
    features = {
        "manifest": {"permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"],
                     "dangerous_permissions": ["android.permission.READ_SMS"], "debuggable": False,
                     "has_launcher_activity": True, "components": {}, "exported_components": [],
                     "package": "com.demo.expfixture", "target_sdk": 34},
        "signing": {"debug_cert": True, "schemes": ["v2"]},
        "strings": {"urls": ["http://c2.demo-sentinel.invalid/beacon"], "ips": [], "flagged_hosts": {}},
        "code": {"categories": {}, "short_name_ratio": 0.1, "reflection_refs": 0},
        "native": {"libs": []}, "files": {}, "reputation": {"yara_hits": []},
    }
    sigs = build_signals(features, {"signal_codes": []})
    codes = [s["code"] for s in sigs]
    assert codes[0] == "SIG-PERM-001"  # high severity first
    assert {"SIG-SIGN-001", "SIG-STR-001", "SIG-PERM-007"} <= set(codes)
    assert [s["id"] for s in sigs] == [f"sig_{i}" for i in range(1, len(sigs) + 1)]
    assert all(s["detail"] for s in sigs)


def test_intake_signal_is_reported_when_zip_unreadable(tmp_path):
    bad = tmp_path / "corrupt.apk"
    bad.write_bytes(b"PK\x03\x04truncated")
    report = open_safely(str(bad))
    assert report.zf is None
    assert report.signals == ["SIG-FILE-900"]
    assert report.partial_reasons


def test_path_traversal_entry_is_recorded_and_flagged(tmp_path):
    p = tmp_path / "evil.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../evil.txt", "x")
        zf.writestr("ok.txt", "y")
    report = open_safely(str(p))
    assert "../evil.txt" in report.unsafe_names
    assert "SIG-FILE-902" in report.signals
    report.zf.close()


def test_archive_ratio_bomb_is_rejected(tmp_path):
    p = tmp_path / "bomb.apk"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * (20 * 1024 * 1024))
    report = open_safely(str(p))
    assert "SIG-FILE-901" in report.signals
    assert report.entries == []
    if report.zf:
        report.zf.close()


def test_rule_yara_escaping_compiles():
    import yara

    from rules.generators import _escape

    text = 'rule t { strings: $a = "' + _escape('http://x.test/a"b\\c') + '" ascii condition: $a }'
    yara.compile(source=text)
