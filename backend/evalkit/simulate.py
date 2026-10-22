"""Demo "Simulate": push two harmless test APKs to the USB-connected phone, offline.

Delivery is `adb install` over the USB cable, so it needs no internet and no Wi-Fi. The phone's install watcher then
detects the new packages and uploads them through the `adb reverse` tunnel (phone 127.0.0.1:<port> -> this server),
which is also local. Nothing here takes a path or a package name from the request: the APK list is fixed below.

Both APKs are inert test fixtures (declared permissions and indicator strings, no executed behaviour), the same ones
the Stage 7 evaluation uses. See android/fixture2 and android/fixture.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from django.conf import settings

from pipeline.events import emit
from sentinel.errors import ApiError

APK_DIR = Path(__file__).resolve().parent / "demo_apks"
APKS = (
    {"file": "malware_test.apk", "package": "com.demo.malwaretest", "label": "Sentinel MALWARE-TEST (harmless)"},
    {"file": "fixture_plain.apk", "package": "com.demo.expfixture", "label": "Sentinel FIXTURE (harmless)"},
)
LEGACY_PHONE_PORT = 8000   # the phone app's old default; tunnelled to the live port so older pairings keep working


def find_adb() -> str | None:
    candidates = [
        os.environ.get("SENTINEL_ADB", ""),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / "adb.exe"),
        str(Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", ""))) / "platform-tools" / "adb"),
        shutil.which("adb") or "",
    ]
    return next((c for c in candidates if c and Path(c).is_file()), None)


def _adb(adb: str, args: list[str], serial: str | None = None, timeout: int = 60) -> tuple[int, str]:
    cmd = [adb] + (["-s", serial] if serial else []) + args
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return done.returncode, (done.stdout + done.stderr).strip()


def connected_devices(adb: str) -> list[str]:
    _, out = _adb(adb, ["devices"], timeout=15)
    return [line.split("\t")[0] for line in out.splitlines()[1:] if line.endswith("\tdevice")]


def simulate(port: int, user=None) -> dict:
    adb = find_adb()
    if not adb:
        raise ApiError("adb_missing", "adb was not found. Install Android platform-tools or set SENTINEL_ADB.", 503)
    devices = connected_devices(adb)
    if not devices:
        raise ApiError("no_device", "No phone is connected over USB (or USB debugging is off).", 409)
    wanted = os.environ.get("SENTINEL_ADB_SERIAL")
    serial = wanted if wanted in devices else devices[0]
    who = user.get_username() if user else None
    open_fresh_window()
    emit(None, "system", "simulate_started", f"Simulation: sending {len(APKS)} test apps to the phone over USB",
         data={"device_serial": serial, "user": who})

    # The phone reaches this server through a USB reverse tunnel, so uploads work with no internet at all.
    tunnel = {}
    for phone_port in sorted({port, LEGACY_PHONE_PORT}):
        rc, out = _adb(adb, ["reverse", f"tcp:{phone_port}", f"tcp:{port}"], serial, timeout=20)
        tunnel[f"tcp:{phone_port}"] = "ok" if rc == 0 else out

    results = []
    for apk in APKS:
        path = APK_DIR / apk["file"]
        if not path.is_file():
            results.append({**apk, "ok": False, "detail": "APK is missing on the server"})
            continue
        rc, out = _adb(adb, ["install", "-r", "-t", str(path)], serial, timeout=180)
        ok = rc == 0 and "Success" in out
        detail = "installed" if ok else (out.splitlines()[-1] if out else f"adb exited {rc}")
        results.append({"file": apk["file"], "package": apk["package"], "label": apk["label"], "ok": ok,
                        "detail": detail})
        emit(None, "system", "simulate_delivered" if ok else "simulate_failed",
             f"{apk['label']}: {'delivered to the phone' if ok else detail}",
             level="info" if ok else "warn", data={"package": apk["package"]})
    return {"device_serial": serial, "tunnel": tunnel, "results": results,
            "delivered": sum(1 for r in results if r["ok"])}


# ---- "fresh analysis" window -------------------------------------------------------------------------------------
# The server normally answers a repeat of the same file from the same phone with the stored verdict (no new work).
# For a simulation that would make the demo look instant and empty, so for a few minutes the two demo packages are
# analysed as new submissions. Stored in SiteSetting under a private key (not part of the dashboard settings API).
FRESH_KEY = "simulate_fresh"
FRESH_SECONDS = 600


def open_fresh_window(seconds: int = FRESH_SECONDS) -> None:
    import time

    from dashboard.models import SiteSetting

    SiteSetting.objects.update_or_create(key=FRESH_KEY, defaults={"value": {"v": {
        "until": time.time() + seconds, "packages": [a["package"] for a in APKS]}}})


def wants_fresh(package_name: str) -> bool:
    import time

    from dashboard.models import SiteSetting

    row = SiteSetting.objects.filter(key=FRESH_KEY).first()
    if row is None:
        return False
    v = (row.value or {}).get("v") or {}
    return time.time() < float(v.get("until", 0)) and package_name in v.get("packages", [])
