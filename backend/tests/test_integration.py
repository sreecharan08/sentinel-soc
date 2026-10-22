"""Integration tests across stages: device API (S2 + S1 contract), pipeline (S2 + S3), remediation (S6),
dashboard roles and API (S5), rules (S6) and security checks. Pipeline runs eagerly (SENTINEL_EAGER=1)."""
import json
from pathlib import Path

import pytest
from django.conf import settings
from jsonschema import Draft202012Validator

from devices.models import Command
from pipeline.models import PipelineEvent
from remediation.models import RemediationRequest
from rules.models import GeneratedRule
from submissions.models import Submission

from .conftest import make_zip_bytes, register_device_via_api, sha256_of, submission_payload

SHARED = Path(settings.BASE_DIR).parent / "shared"


def _schema(name):
    return json.loads((SHARED / name).read_text(encoding="utf-8"))


def _upload(client, sub_id, data: bytes, declared=None):
    return client.generic("PUT", f"/api/v1/submissions/{sub_id}/apk", data=data,
                          content_type="application/octet-stream",
                          HTTP_X_CONTENT_SHA256=declared or sha256_of(data))


def _device_submit(client, data: bytes, **extra):
    resp = client.post("/api/v1/submissions", submission_payload(data, **extra), format="json")
    assert resp.status_code == 201, resp.content
    return resp.json()


# ---------------------------------------------------------------- S2 device API, pairing and auth (API-01..03)
@pytest.mark.django_db
def test_pairing_code_is_single_use_and_returns_a_token(client):
    from devices.pairing import create_pairing_code

    code = create_pairing_code()
    ok = client.post("/api/v1/devices/register", {"pairing_code": code.code, "device_name": "A"}, format="json")
    assert ok.status_code == 201
    assert len(ok.json()["device_token"]) >= 40
    again = client.post("/api/v1/devices/register", {"pairing_code": code.code, "device_name": "B"}, format="json")
    assert again.status_code == 400
    assert again.json()["error"]["code"] == "pairing_failed"


@pytest.mark.django_db
def test_pairing_is_throttled_after_five_attempts(client):
    for _ in range(5):
        client.post("/api/v1/devices/register", {"pairing_code": "000000"}, format="json")
    resp = client.post("/api/v1/devices/register", {"pairing_code": "000000"}, format="json")
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"


@pytest.mark.django_db
def test_bad_device_token_gets_contract_invalid_token(client):
    client.credentials(HTTP_AUTHORIZATION="Device not-a-real-token")
    resp = client.post("/api/v1/devices/me/heartbeat", {"app_version": "0.1.0", "protection_on": True}, format="json")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_token"


@pytest.mark.django_db
def test_heartbeat_updates_last_seen(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    resp = client.post("/api/v1/devices/me/heartbeat", {"app_version": "0.1.1", "protection_on": False}, format="json")
    assert resp.status_code == 204
    from devices.models import Device

    dev = Device.objects.get(pk=reg["device_id"])
    assert dev.last_seen is not None and dev.protection_on is False and dev.app_version == "0.1.1"


# ---------------------------------------------------------------- S2 upload integrity (API-03..05)
@pytest.mark.django_db
def test_upload_with_wrong_bytes_is_rejected_and_nothing_is_stored(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes()
    body = _device_submit(client, data)
    assert body["need_upload"] is True
    # Valid ZIP magic, different content: passes the magic check and fails the fingerprint check.
    tampered = make_zip_bytes({"tamper.txt": "changed"})
    resp = _upload(client, body["submission_id"], tampered, declared=sha256_of(data))
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "hash_mismatch"
    assert not (settings.SENTINEL["MEDIA_SAMPLES"]).exists() or not list(settings.SENTINEL["MEDIA_SAMPLES"].rglob("*.apk"))


@pytest.mark.django_db
def test_non_zip_is_rejected_as_not_an_apk(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = b"this is plain text, not a package"
    body = _device_submit(client, data)
    resp = _upload(client, body["submission_id"], data)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "not_an_apk"


@pytest.mark.django_db
def test_oversized_declared_size_is_refused_before_upload(client, settings):
    settings.SENTINEL = dict(settings.SENTINEL, MAX_APK_MB=1)
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes()
    resp = client.post("/api/v1/submissions", submission_payload(data, apk_size_bytes=5 * 1024 * 1024), format="json")
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "apk_too_large"


# ---------------------------------------------------------------- S2 end to end: upload -> pipeline -> commands
@pytest.mark.django_db
def test_full_device_flow_reaches_verdict_and_notifies_phone(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes()
    body = _device_submit(client, data)
    assert body["status"] == "awaiting_upload"
    up = _upload(client, body["submission_id"], data)
    assert up.status_code == 202

    status_resp = client.get(f"/api/v1/submissions/{body['submission_id']}")
    payload = status_resp.json()
    assert payload["status"] == "verdict_ready"
    assert payload["status_label"] == "Done"
    assert payload["verdict"]["label"] in ("malicious", "suspicious", "benign", "unknown")
    assert payload["verdict"]["provider"].startswith("rule_engine v")
    # Evidence behind the verdict for the phone's "why" screen and threat graph.
    assert isinstance(payload["verdict"]["signals"], list)
    assert set(payload["verdict"]["iocs"]) == {"urls", "domains", "ips", "flagged_hosts", "telegram_bot"}
    sev = [s["severity"] for s in payload["verdict"]["signals"]]
    assert sev == sorted(sev, key=lambda s: {"high": 0, "medium": 1, "low": 2}.get(s, 3))
    # Pipeline timeline, oldest first, ending with the stored verdict.
    stages = [(e["stage"], e["step"]) for e in payload["timeline"]]
    assert stages[0] == ("intake", "submission_received")
    assert ("verdict", "stored") in stages

    polled = client.get("/api/v1/devices/me/commands?cursor=0").json()
    types = [c["type"] for c in polled["commands"]]
    assert "verdict_notify" in types
    cmd = next(c for c in polled["commands"] if c["type"] == "verdict_notify")
    assert cmd["payload"]["package_name"] == "com.demo.expfixture"
    ack = client.post(f"/api/v1/devices/me/commands/{cmd['id']}/ack")
    assert ack.status_code == 204
    again = client.post(f"/api/v1/devices/me/commands/{cmd['id']}/ack")
    assert again.status_code == 204  # idempotent
    after = client.get(f"/api/v1/devices/me/commands?cursor={polled['next_cursor']}").json()
    assert after["commands"] == [] and after["next_cursor"] == polled["next_cursor"]


@pytest.mark.django_db
def test_pipeline_records_the_evidence_chain_in_order():
    client_data = make_zip_bytes()
    from django.test import Client
    from devices.pairing import create_pairing_code

    c = Client()
    code = create_pairing_code()
    reg = c.post("/api/v1/devices/register", data=json.dumps({"pairing_code": code.code}),
                 content_type="application/json").json()
    c.defaults["HTTP_AUTHORIZATION"] = f"Device {reg['device_token']}"
    body = c.post("/api/v1/submissions", data=json.dumps(submission_payload(client_data)),
                  content_type="application/json").json()
    c.generic("PUT", f"/api/v1/submissions/{body['submission_id']}/apk", data=client_data,
              content_type="application/octet-stream", HTTP_X_CONTENT_SHA256=sha256_of(client_data))
    steps = list(PipelineEvent.objects.filter(submission_id=body["submission_id"]).order_by("id")
                 .values_list("stage", "step"))
    order = [("intake", "submission_received"), ("intake", "upload_received"), ("static_analysis", "started"),
             ("reasoning", "started"), ("verdict", "stored")]
    positions = [steps.index(s) for s in order]
    assert positions == sorted(positions)


@pytest.mark.django_db
def test_same_file_from_second_phone_is_a_cache_hit(client):
    data = make_zip_bytes()
    reg1 = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg1['device_token']}")
    first = _device_submit(client, data)
    _upload(client, first["submission_id"], data)

    from devices.pairing import create_pairing_code
    from rest_framework.test import APIClient

    code = create_pairing_code()
    second_client = APIClient()
    reg2 = second_client.post("/api/v1/devices/register", {"pairing_code": code.code, "device_name": "Other"},
                              format="json").json()
    second_client.credentials(HTTP_AUTHORIZATION=f"Device {reg2['device_token']}")
    second = _device_submit(second_client, data)
    assert second["need_upload"] is False
    assert second["cached_verdict"]["label"] in ("malicious", "suspicious", "benign", "unknown")
    assert Submission.objects.get(pk=second["submission_id"]).status == "verdict_ready"


@pytest.mark.django_db
def test_submission_of_another_device_is_not_visible(client):
    reg1 = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg1['device_token']}")
    body = _device_submit(client, make_zip_bytes())

    from devices.pairing import create_pairing_code
    from rest_framework.test import APIClient

    other = APIClient()
    code = create_pairing_code()
    reg2 = other.post("/api/v1/devices/register", {"pairing_code": code.code}, format="json").json()
    other.credentials(HTTP_AUTHORIZATION=f"Device {reg2['device_token']}")
    assert other.get(f"/api/v1/submissions/{body['submission_id']}").status_code == 404


@pytest.mark.django_db
def test_verdict_payload_validates_against_contract_schema(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes()
    body = _device_submit(client, data)
    _upload(client, body["submission_id"], data)
    sub = Submission.objects.get(pk=body["submission_id"])
    verdict = sub.verdicts.get(is_current=True)
    Draft202012Validator(_schema("verdict.schema.json")).validate(verdict.payload)
    from analysis.models import Analysis

    evidence = Analysis.objects.get(sample=sub.sample).evidence
    Draft202012Validator(_schema("evidence.schema.json")).validate(evidence)


# ---------------------------------------------------------------- S6 remediation lifecycle (T6-06..09)
def _verdict_submission(client, malicious=True):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes({"pad.bin": str(malicious)})
    body = _device_submit(client, data)
    _upload(client, body["submission_id"], data)
    return reg, body["submission_id"]


@pytest.mark.django_db
def test_t6_06_full_uninstall_lifecycle(client, analyst_client):
    reg, sid = _verdict_submission(client)
    resp = analyst_client.post(f"/api/v1/dash/submissions/{sid}/remediation", {"action": "uninstall", "note": "demo"},
                               format="json")
    assert resp.status_code == 201, resp.content
    rid = resp.json()["remediation_id"]
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    cmds = [c for c in client.get("/api/v1/devices/me/commands?cursor=0").json()["commands"]
            if c["type"] == "uninstall_proposed"]
    assert cmds and cmds[0]["payload"]["remediation_id"] == rid
    client.post(f"/api/v1/devices/me/commands/{cmds[0]['id']}/ack")
    assert RemediationRequest.objects.get(pk=rid).state == "delivered"
    ok = client.post(f"/api/v1/remediations/{rid}/result", {"outcome": "uninstalled", "detail": ""}, format="json")
    assert ok.status_code == 204
    assert RemediationRequest.objects.get(pk=rid).state == "completed"


@pytest.mark.django_db
def test_t6_07_conflicting_result_is_409(client, analyst_client):
    reg, sid = _verdict_submission(client)
    rid = analyst_client.post(f"/api/v1/dash/submissions/{sid}/remediation", {"action": "uninstall"},
                              format="json").json()["remediation_id"]
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    assert client.post(f"/api/v1/remediations/{rid}/result", {"outcome": "declined"}, format="json").status_code == 204
    conflict = client.post(f"/api/v1/remediations/{rid}/result", {"outcome": "uninstalled"}, format="json")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "state_conflict"
    same = client.post(f"/api/v1/remediations/{rid}/result", {"outcome": "declined"}, format="json")
    assert same.status_code == 204


@pytest.mark.django_db
def test_t6_09_cancel_while_delivered_tells_phone_and_blocks_result(client, analyst_client):
    reg, sid = _verdict_submission(client)
    rid = analyst_client.post(f"/api/v1/dash/submissions/{sid}/remediation", {"action": "uninstall"},
                              format="json").json()["remediation_id"]
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    cmd = next(c for c in client.get("/api/v1/devices/me/commands?cursor=0").json()["commands"]
               if c["type"] == "uninstall_proposed")
    client.post(f"/api/v1/devices/me/commands/{cmd['id']}/ack")
    assert analyst_client.post(f"/api/v1/dash/remediations/{rid}/cancel", {"note": "wrong app"}, format="json") \
        .status_code == 200
    later = client.get("/api/v1/devices/me/commands?cursor=0").json()["commands"]
    assert any(c["type"] == "uninstall_cancelled" for c in later)
    assert client.post(f"/api/v1/remediations/{rid}/result", {"outcome": "uninstalled"}, format="json").status_code == 409


@pytest.mark.django_db
def test_remediation_requires_an_analyst(client, viewer_client):
    reg, sid = _verdict_submission(client)
    resp = viewer_client.post(f"/api/v1/dash/submissions/{sid}/remediation", {"action": "uninstall"}, format="json")
    assert resp.status_code == 403


# ---------------------------------------------------------------- S5 dashboard roles and API (UI-03, SEC-01)
@pytest.mark.django_db
def test_unauthenticated_dashboard_api_is_refused(client):
    resp = client.get("/api/v1/dash/stats")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


@pytest.mark.django_db
def test_viewer_can_read_but_not_write(viewer_client, analyst_client):
    assert viewer_client.get("/api/v1/dash/stats").status_code == 200
    assert viewer_client.post("/api/v1/dash/pairing-code", {}, format="json").status_code == 403
    assert analyst_client.post("/api/v1/dash/pairing-code", {}, format="json").status_code == 201


@pytest.mark.django_db
def test_analyst_override_changes_effective_label_and_notifies_device(client, analyst_client):
    reg, sid = _verdict_submission(client)
    resp = analyst_client.post(f"/api/v1/dash/submissions/{sid}/override",
                               {"label": "benign", "note": "vendor app, false positive"}, format="json")
    assert resp.status_code == 200
    assert resp.json()["label"] == "benign" and resp.json()["overridden"] is True
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    latest = client.get("/api/v1/devices/me/commands?cursor=0").json()["commands"][-1]
    assert latest["type"] == "verdict_notify" and latest["payload"]["label"] == "benign"
    assert client.get(f"/api/v1/submissions/{sid}").json()["verdict"]["label"] == "benign"


@pytest.mark.django_db
def test_override_note_too_short_is_rejected(client, analyst_client):
    _, sid = _verdict_submission(client)
    resp = analyst_client.post(f"/api/v1/dash/submissions/{sid}/override", {"label": "benign", "note": "no"},
                               format="json")
    assert resp.status_code == 400


@pytest.mark.django_db
def test_stats_and_list_endpoints_render_shapes(client, analyst_client):
    _verdict_submission(client)
    stats = analyst_client.get("/api/v1/dash/stats").json()
    assert {"devices_online", "submissions_today", "by_label", "in_progress", "pending_remediations"} <= set(stats)
    rows = analyst_client.get("/api/v1/dash/submissions?page_size=5").json()
    assert rows["count"] >= 1 and rows["results"][0]["package_name"] == "com.demo.expfixture"
    filtered = analyst_client.get("/api/v1/dash/submissions?label=malicious&status=in_progress").json()
    assert filtered["count"] == 0


@pytest.mark.django_db
def test_pages_render_for_logged_in_users_and_redirect_otherwise(client, analyst_client):
    assert client.get("/").status_code == 302
    for path in ("/", "/submissions/", "/devices/", "/remediation/", "/rules/", "/settings/", "/demo/"):
        resp = analyst_client.get(path)
        assert resp.status_code == 200, path
        assert b'id="page-data"' in resp.content
        assert resp.headers.get("Content-Security-Policy", "").startswith("default-src 'self'")
        assert resp.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.django_db
def test_stored_apk_is_not_web_accessible(analyst_client, client):
    samples = settings.SENTINEL["MEDIA_SAMPLES"] / "aa"
    samples.mkdir(parents=True, exist_ok=True)
    (samples / ("aa" * 32 + ".apk")).write_bytes(b"PK\x03\x04")
    assert client.get(f"/media/samples/aa/{'aa' * 32}.apk").status_code == 404
    assert client.get(f"/static/../samples/aa/{'aa' * 32}.apk").status_code in (404, 400)


@pytest.mark.django_db
def test_hostile_label_is_returned_as_plain_json_string(client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes()
    body = _device_submit(client, data, app_label="<script>alert(1)</script>")
    _upload(client, body["submission_id"], data)
    assert Submission.objects.get(pk=body["submission_id"]).app_label == "<script>alert(1)</script>"


# ---------------------------------------------------------------- S6 rules on a real fixture (T6-10..15)
@pytest.mark.django_db
def test_rules_from_fixture_compile_self_test_and_wait_for_approval(client, analyst_client, fixture_apk):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = fixture_apk.read_bytes()
    body = _device_submit(client, data)
    _upload(client, body["submission_id"], data)
    sub = Submission.objects.get(pk=body["submission_id"])
    assert sub.status == "verdict_ready"
    yara_rules = list(GeneratedRule.objects.filter(kind="yara", source_sha256=sub.sample.sha256))
    if sub.verdicts.get(is_current=True).label != "malicious":
        pytest.skip("fixture verdict is not malicious; rule generation is for malicious verdicts")
    assert yara_rules, "a malicious fixture should yield a YARA draft"
    rule = yara_rules[0]
    assert rule.status == "draft" and "uint32(0) == 0x0a786564" in rule.content
    assert rule.fp_test["self_test"] is True
    # No benign corpus in the test environment: FP test is not_run, so approval needs a note (T6-14).
    rejected = analyst_client.post(f"/api/v1/dash/rules/{rule.id}/approve", {"note": ""}, format="json")
    assert rejected.status_code == 400
    approved = analyst_client.post(f"/api/v1/dash/rules/{rule.id}/approve", {"note": "fixture rule"}, format="json")
    assert approved.status_code == 200
    rule.refresh_from_db()
    assert rule.status == "approved"
    active = settings.SENTINEL["RULES_DIR"] / "active" / "yara" / f"{rule.name}.yar"
    assert active.exists()
    # T6-15: the approved rule is compiled by the static analyzer for the next scan of the same bytes.
    from analysis.analyzers.reputation import compile_rules

    rules, errors = compile_rules()
    assert rules is not None and not errors
    export = analyst_client.get("/api/v1/dash/rules/export")
    assert export.status_code == 200 and export.headers["Content-Type"] == "application/zip"
    retire = analyst_client.post(f"/api/v1/dash/rules/{rule.id}/retire", {"note": "done"}, format="json")
    assert retire.status_code == 200
    assert not active.exists()


def test_generic_only_evidence_is_skipped_with_reason():
    from rules.generators import select_strings

    evidence = {"static": {"strings": {"urls": [], "domains": [], "ips": []},
                           "manifest": {"components": {}}, "files": {}, "code": {"api_hits": []}}}
    chosen, reason = select_strings(evidence, None)
    assert chosen == [] and reason == "not enough specific strings"


@pytest.mark.django_db
def test_policy_blocks_protected_package_for_analyst_too(client, analyst_client):
    reg = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg['device_token']}")
    data = make_zip_bytes({"x.bin": "y"})
    body = _device_submit(client, data, package_name="com.android.chrome")
    _upload(client, body["submission_id"], data)
    resp = analyst_client.post(f"/api/v1/dash/submissions/{body['submission_id']}/remediation",
                               {"action": "uninstall"}, format="json")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"


@pytest.mark.django_db
def test_events_endpoint_resumes_from_event_id(client, analyst_client):
    _, sid = _verdict_submission(client)
    first = analyst_client.get(f"/api/v1/dash/submissions/{sid}/events?since_event_id=0").json()["events"]
    assert first and all(e["v"] == 1 for e in first)
    last = first[-1]["event_id"]
    rest = analyst_client.get(f"/api/v1/dash/submissions/{sid}/events?since_event_id={last}").json()["events"]
    assert rest == []


@pytest.mark.django_db
def test_healthz_reports_db_and_eager_worker(client):
    resp = client.get("/healthz")
    body = resp.json()
    assert body["db"] is True and body["workers"] >= 1
    assert resp.status_code == 200 and body["ok"] is True


@pytest.mark.django_db
def test_requeue_stale_is_idempotent_for_missing_work():
    from pipeline.tasks import requeue_stale

    assert requeue_stale() == 0


@pytest.mark.django_db
def test_command_queue_is_per_device(client):
    reg1 = register_device_via_api(client)
    client.credentials(HTTP_AUTHORIZATION=f"Device {reg1['device_token']}")
    data = make_zip_bytes()
    body = _device_submit(client, data)
    _upload(client, body["submission_id"], data)
    other = Command.objects.exclude(device_id=reg1["device_id"]).count()
    assert other == 0
