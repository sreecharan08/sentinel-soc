"""Next.js dashboard contract: JWT auth, aggregate endpoints, provider path surfacing, WebSocket token auth."""
import asyncio

import pytest
from django.contrib.auth.models import Group, User
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


def _user(name="webanalyst", analyst=True, password="pw-12345"):
    user = User.objects.create_user(name, password=password)
    if analyst:
        user.groups.add(Group.objects.get_or_create(name="analyst")[0])
    return user


def _login(client, name="webanalyst", password="pw-12345"):
    return client.post("/api/v1/auth/token/", {"username": name, "password": password}, format="json")


def test_login_returns_tokens_and_role():
    _user()
    res = _login(APIClient())
    assert res.status_code == 200
    assert {"access", "refresh", "user"} <= set(res.data)
    assert res.data["user"] == {"username": "webanalyst", "role": "analyst"}


def test_bad_password_is_401_with_contract_error_body():
    _user()
    res = _login(APIClient(), password="nope")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "invalid_credentials"


def test_bearer_token_authenticates_dash_api_and_anonymous_is_rejected():
    _user()
    client = APIClient()
    assert client.get("/api/v1/dash/stats").status_code == 403
    token = _login(client).data["access"]
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    res = client.get("/api/v1/dash/stats")
    assert res.status_code == 200 and "by_label" in res.json() and "ttv_p95_s" in res.json()


def test_garbage_bearer_token_is_401_token_invalid():
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Bearer not-a-jwt")
    res = client.get("/api/v1/dash/stats")
    assert res.status_code == 401 and res.json()["error"]["code"] == "token_invalid"


def test_refresh_issues_new_access_token_and_me_reports_role():
    _user("viewonly", analyst=False)
    client = APIClient()
    refresh = _login(client, "viewonly").data["refresh"]
    access = client.post("/api/v1/auth/refresh/", {"refresh": refresh}, format="json").data["access"]
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    assert client.get("/api/v1/auth/me/").json() == {"username": "viewonly", "role": "viewer"}
    assert client.post("/api/v1/dash/pairing-code").status_code == 403    # viewers cannot write


@pytest.mark.parametrize("path", ["events", "network", "graph", "pipeline", "remediation-queue", "devices",
                                  "rules", "settings", "remediations", "submissions"])
def test_every_page_endpoint_responds_for_authenticated_viewer(path):
    _user("v2", analyst=False)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {_login(client, 'v2').data['access']}")
    res = client.get(f"/api/v1/dash/{path}")
    assert res.status_code == 200, res.content


def test_provider_info_distinguishes_every_path():
    from types import SimpleNamespace as NS

    from dashboard.payloads import provider_info

    def v(name, detail=None, fallback=None, trace=()):
        payload = {"provider": {"detail": detail} if detail else {}, "agentic_trace": list(trace)}
        return NS(provider_name=name, provider_version="0.1", fallback_from=fallback, payload=payload)

    assert provider_info(v("rule_engine"))["provider_path"] == "rule_engine"
    assert provider_info(v("rule_engine"))["provider_detail"] == "rule_engine v0.1"
    agentic = provider_info(v("rule_engine+agentic", "rule_engine v0.1 + qwen2.5:3b-instruct (agentic, 2 tool calls)",
                              trace=[{"type": "tool_call"}, {"type": "tool_call"}, {"type": "conclude"}]))
    assert agentic["provider_path"] == "agentic" and agentic["tool_calls"] == 2
    assert provider_info(v("active_list_match"))["provider_path"] == "active_list"
    assert provider_info(v("rule_engine", fallback="hybrid"))["provider_path"] == "fallback"


@pytest.mark.django_db(transaction=True)
def test_websocket_accepts_valid_token_and_rejects_missing_or_bad_token():
    from channels.testing import WebsocketCommunicator

    from sentinel.asgi import application

    _user("wsuser")
    access = _login(APIClient(), "wsuser").data["access"]

    async def connect(query):
        comm = WebsocketCommunicator(application, f"/ws/dashboard/{query}")
        ok, _ = await comm.connect()
        if ok:
            await comm.disconnect()
        return ok

    assert asyncio.run(connect(f"?token={access}")) is True
    assert asyncio.run(connect("")) is False
    assert asyncio.run(connect("?token=garbage")) is False


@pytest.mark.django_db(transaction=True)
def test_device_websocket_needs_device_token_and_receives_its_own_events(device):
    from asgiref.sync import sync_to_async
    from channels.testing import WebsocketCommunicator

    from pipeline.events import emit
    from sentinel.asgi import application
    from submissions.models import Sample, Submission

    sub = Submission.objects.create(device=device, sample=Sample.objects.create(sha256="a" * 64),
                                    package_name="com.demo.expfixture")

    async def run(auth):
        headers = [(b"authorization", auth.encode())] if auth else []
        comm = WebsocketCommunicator(application, "/ws/device/", headers=headers)
        ok, _ = await comm.connect()
        if not ok:
            return False, None
        await sync_to_async(emit)(sub, "verdict", "stored", "Verdict stored")
        msg = await comm.receive_json_from(timeout=3)
        await comm.disconnect()
        return True, msg

    ok, msg = asyncio.run(run(f"Device {device.raw_token}"))
    assert ok and msg["submission_id"] == str(sub.id) and msg["step"] == "stored"
    assert asyncio.run(run(""))[0] is False
    assert asyncio.run(run("Device garbage"))[0] is False


def test_graph_links_apps_through_shared_and_flagged_iocs():
    from analysis.models import Analysis
    from devices.models import Device
    from submissions.models import Sample, Submission, Verdict

    def app(pkg, sha, urls=(), flagged=None, ips=()):
        dev = Device.objects.get_or_create(name="graph phone", defaults={"token_hash": "x" * 64})[0]
        sample = Sample.objects.create(sha256=sha)
        analysis = Analysis.objects.create(sample=sample, analysis_version=1, evidence={
            "static": {"strings": {"urls": list(urls), "ips": list(ips), "flagged_hosts": flagged or {}}}, "signals": []})
        sub = Submission.objects.create(device=dev, sample=sample, package_name=pkg, status="verdict_ready")
        Verdict.objects.create(submission=sub, analysis=analysis, label="suspicious", provider_name="rule_engine",
                               provider_version="0.1", is_current=True)
        return sub

    a = app("com.a", "a" * 64, urls=["https://cdn.shared.example/x", "https://only-a.example/y"])
    b = app("com.b", "b" * 64, urls=["http://cdn.shared.example/z"], flagged={"bit.ly": "shortener"})
    _user("graphviewer", analyst=False)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {_login(client, 'graphviewer').data['access']}")
    body = client.get("/api/v1/dash/graph").json()

    by_value = {i["value"]: i for i in body["iocs"]}
    assert sorted(by_value["cdn.shared.example"]["app_ids"]) == sorted([str(a.id), str(b.id)])
    assert by_value["bit.ly"]["flagged"] is True and by_value["bit.ly"]["app_ids"] == [str(b.id)]
    assert "only-a.example" not in by_value        # single app, not flagged: no correlation, no node
    assert body["shared_iocs"] == 1


def test_simulate_installs_the_two_demo_apks_and_sets_up_the_usb_tunnel(monkeypatch):
    from evalkit import simulate as sim

    calls = []

    def fake_adb(adb, args, serial=None, timeout=60):
        calls.append((serial, args))
        return 0, "Success" if args and args[0] == "install" else ""

    monkeypatch.setattr(sim, "find_adb", lambda: "adb")
    monkeypatch.setattr(sim, "connected_devices", lambda adb: ["PHONE1"])
    monkeypatch.setattr(sim, "_adb", fake_adb)
    _user("simanalyst")
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {_login(client, 'simanalyst').data['access']}")
    res = client.post("/api/v1/dash/demo/simulate", {}, format="json")
    assert res.status_code == 200, res.content
    body = res.json()
    assert body["delivered"] == 2 and body["device_serial"] == "PHONE1"
    assert {r["package"] for r in body["results"]} == {"com.demo.malwaretest", "com.demo.expfixture"}
    installs = [a for s, a in calls if a[0] == "install"]
    assert len(installs) == 2 and all(a[:3] == ["install", "-r", "-t"] for a in installs)
    assert any(a[0] == "reverse" for _, a in calls)          # tunnel is (re)established before installing


def test_simulate_reports_no_phone_and_is_analyst_only(monkeypatch):
    from evalkit import simulate as sim

    monkeypatch.setattr(sim, "find_adb", lambda: "adb")
    monkeypatch.setattr(sim, "connected_devices", lambda adb: [])
    _user("simviewer", analyst=False)
    viewer = APIClient()
    viewer.credentials(HTTP_AUTHORIZATION=f"Bearer {_login(viewer, 'simviewer').data['access']}")
    assert viewer.post("/api/v1/dash/demo/simulate", {}, format="json").status_code == 403
    _user("simanalyst2")
    analyst = APIClient()
    analyst.credentials(HTTP_AUTHORIZATION=f"Bearer {_login(analyst, 'simanalyst2').data['access']}")
    res = analyst.post("/api/v1/dash/demo/simulate", {}, format="json")
    assert res.status_code == 409 and res.json()["error"]["code"] == "no_device"


def test_simulate_fresh_window_bypasses_dedupe_for_demo_packages_only():
    from devices.models import Device
    from evalkit.simulate import open_fresh_window, wants_fresh
    from submissions.models import Sample, Submission
    from submissions.services import create_submission

    dev = Device.objects.create(name="simphone", token_hash="y" * 64)
    sha = "c" * 64
    sample = Sample.objects.create(sha256=sha)
    old = Submission.objects.create(device=dev, sample=sample, package_name="com.demo.malwaretest",
                                    status="verdict_ready")
    data = {"apk_sha256": sha, "apk_size_bytes": 1, "package_name": "com.demo.malwaretest"}
    assert create_submission(dev, data)[0].id == old.id              # normal: the earlier submission is reused
    open_fresh_window()
    assert wants_fresh("com.demo.malwaretest") and not wants_fresh("com.other.app")
    fresh, _, _ = create_submission(dev, data)
    assert fresh.id != old.id                                         # inside the window: a new submission
