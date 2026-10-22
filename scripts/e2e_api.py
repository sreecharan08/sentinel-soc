"""End-to-end test over real HTTP against the running stack (Daphne + Redis + Celery worker).

Plays both sides: the phone (device API) and an analyst (dashboard session API).
Usage: python scripts/e2e_api.py --base http://127.0.0.1:8000 --fixture backend/tests/fixtures/exp_plain.apk
"""
import argparse
import hashlib
import http.cookiejar
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
PY = BACKEND / ".venv" / "Scripts" / "python.exe"


class Client:
    def __init__(self, base, token=None):
        self.base = base.rstrip("/")
        self.token = token
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, raw=None, headers=None, expect=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if body is not None and raw is None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Device {self.token}")
        csrf = next((c.value for c in self.jar if c.name == "csrftoken"), None)
        if csrf and method not in ("GET", "HEAD"):
            req.add_header("X-CSRFToken", csrf)
            req.add_header("Referer", self.base + "/")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=60) as resp:
                text = resp.read().decode()
                status = resp.status
        except urllib.error.HTTPError as exc:
            text = exc.read().decode()
            status = exc.code
        try:
            parsed = json.loads(text) if text else {}
        except json.JSONDecodeError:
            parsed = {"_text": text[:200]}
        if expect is not None:
            assert status == expect, f"{method} {path} -> {status}, expected {expect}: {text[:300]}"
        return status, parsed


def step(name):
    print(f"\n== {name}")


def check(cond, msg):
    print(("   PASS " if cond else "   FAIL ") + msg)
    if not cond:
        sys.exit(1)


def manage(*args):
    out = subprocess.run([str(PY), "manage.py", *args], cwd=BACKEND, capture_output=True, text=True,
                         env={**__import__("os").environ, "REDIS_URL": "redis://127.0.0.1:6379/0"})
    return out.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--fixture", default=str(BACKEND / "tests" / "fixtures" / "exp_plain.apk"))
    ap.add_argument("--analyst-user", default="analyst")
    ap.add_argument("--analyst-pass", required=True)
    args = ap.parse_args()

    apk = Path(args.fixture).read_bytes()
    sha = hashlib.sha256(apk).hexdigest()
    anon = Client(args.base)

    step("0. server health")
    status, health = anon.call("GET", "/healthz")
    check(status == 200 and health.get("ok") is True, f"healthz ok: {health}")

    step("1. pair a phone with a real one-time code")
    code = re.search(r"^(\d{6})$", manage("pair_code").split("\n")[0].strip(), re.M).group(1)
    status, reg = anon.call("POST", "/api/v1/devices/register",
                            {"pairing_code": code, "device_name": "e2e-phone", "android_version": "14",
                             "app_version": "0.1.0"})
    check(status == 201 and reg.get("device_token"), f"registered device {reg.get('device_id', '')[:8]}")
    phone = Client(args.base, token=reg["device_token"])
    status, _ = anon.call("POST", "/api/v1/devices/register",
                          {"pairing_code": code, "device_name": "reuse"})
    check(status == 400, "the same pairing code is rejected the second time")

    step("2. install event: submit metadata, upload the APK")
    meta = {"package_name": "com.demo.expfixture", "app_label": "Exp Fixture", "version_name": "1.0",
            "version_code": 1, "installer_package": None, "first_install_time": "2026-10-05T09:30:00Z",
            "requested_permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"],
            "apk_sha256": sha, "apk_size_bytes": len(apk), "split_count": 0}
    status, sub = phone.call("POST", "/api/v1/submissions", meta)
    check(status == 201, f"submission created (need_upload={sub.get('need_upload')})")
    sid = sub["submission_id"]
    if sub.get("need_upload"):
        status, _ = phone.call("PUT", f"/api/v1/submissions/{sid}/apk", raw=apk,
                               headers={"Content-Type": "application/octet-stream", "X-Content-SHA256": sha})
        check(status == 202, "APK uploaded and hash verified")

    step("3. pipeline runs on the Celery worker to a verdict")
    final = {}
    for _ in range(120):
        _, final = phone.call("GET", f"/api/v1/submissions/{sid}")
        if final.get("status") in ("verdict_ready", "error"):
            break
        time.sleep(1)
    check(final.get("status") == "verdict_ready", f"status reached verdict_ready (got {final.get('status')})")
    v = final.get("verdict") or {}
    check(v.get("label") in ("malicious", "suspicious", "benign", "unknown"), f"verdict label {v.get('label')}")
    check(str(v.get("provider", "")).startswith("rule_engine"), f"provider shown: {v.get('provider')}")

    step("4. phone receives verdict_notify and acks it")
    _, polled = phone.call("GET", "/api/v1/devices/me/commands?cursor=0")
    notify = [c for c in polled["commands"] if c["type"] == "verdict_notify"]
    check(bool(notify), "verdict_notify delivered by polling")
    phone.call("POST", f"/api/v1/devices/me/commands/{notify[-1]['id']}/ack", expect=204)

    step("5. analyst logs in to the dashboard and reads the API")
    anon.call("GET", "/login/")  # sets csrftoken
    status, _ = anon.call("POST", "/login/", raw=(f"username={args.analyst_user}&password={args.analyst_pass}"
                                                  f"&csrfmiddlewaretoken="
                                                  + next((c.value for c in anon.jar if c.name == 'csrftoken'), ''))
                          .encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    status, stats = anon.call("GET", "/api/v1/dash/stats")
    check(status == 200 and "by_label" in stats, f"dashboard stats readable (devices_online={stats.get('devices_online')})")
    status, rows = anon.call("GET", f"/api/v1/dash/submissions?q=com.demo.expfixture")
    check(status == 200 and rows.get("count", 0) >= 1, "submission listed on the dashboard")
    status, detail = anon.call("GET", f"/api/v1/dash/submissions/{sid}")
    check(status == 200 and detail["evidence"] is not None, "evidence stored and visible in the detail")
    status, ev = anon.call("GET", f"/api/v1/dash/submissions/{sid}/events?since_event_id=0")
    steps = [(e["stage"], e["step"]) for e in ev.get("events", [])]
    cached = ("intake", "cache_hit") in steps  # same bytes analysed before: the server reuses the verdict
    analysed = ("reasoning", "finished") in steps and ("verdict", "stored") in steps
    check(cached or analysed, f"evidence chain has {len(steps)} events "
          f"({'cache hit: verdict reused' if cached else 'full analysis: reasoning + verdict'})")

    step("6. analyst proposes an uninstall; phone gets it; user confirms; outcome verified")
    status, prop = anon.call("POST", f"/api/v1/dash/submissions/{sid}/remediation", {"action": "uninstall",
                                                                                     "note": "e2e test"})
    if status == 201:
        rid = prop["remediation_id"]
        check(True, "uninstall proposed (guardrails passed)")
        _, polled = phone.call("GET", "/api/v1/devices/me/commands?cursor=0")
        prop_cmd = [c for c in polled["commands"] if c["type"] == "uninstall_proposed"]
        check(bool(prop_cmd), "phone received uninstall_proposed")
        phone.call("POST", f"/api/v1/devices/me/commands/{prop_cmd[-1]['id']}/ack", expect=204)
        _, state = anon.call("GET", f"/api/v1/dash/submissions/{sid}")
        check(state["remediation"]["state"] == "delivered", "remediation state is delivered after ack")
        phone.call("POST", f"/api/v1/remediations/{rid}/result", {"outcome": "uninstalled", "detail": "e2e"}, expect=204)
        _, state = anon.call("GET", f"/api/v1/dash/submissions/{sid}")
        check(state["remediation"]["state"] == "completed", "remediation completed after device report")
    else:
        print(f"   note: proposal blocked by guardrails ({status}): {prop.get('error', {}).get('message')}")

    step("7. override is audited and pushed to the phone")
    status, _ = anon.call("POST", f"/api/v1/dash/submissions/{sid}/override",
                          {"label": "benign", "note": "e2e: reviewed, false positive"})
    check(status == 200, "override saved")
    _, polled = phone.call("GET", "/api/v1/devices/me/commands?cursor=0")
    check(any(c["type"] == "verdict_notify" and c["payload"].get("label") == "benign" for c in polled["commands"]),
          "phone told the new label")

    step("8. dashboard pages render")
    for path in ("/", "/submissions/", f"/submissions/{sid}/", "/devices/", "/remediation/", "/rules/", "/settings/", "/demo/"):
        status, _ = anon.call("GET", path)
        check(status == 200, f"GET {path} -> {status}")

    # Clean up the test device and its data so repeated runs do not leave duplicates on the dashboard.
    manage("shell", "-c", f"from devices.models import Device; Device.objects.filter(pk='{reg['device_id']}').delete()")
    print("\nE2E API: all checks passed. Test device removed.")


if __name__ == "__main__":
    main()
