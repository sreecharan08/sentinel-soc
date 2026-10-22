"""Shared fixtures and helpers for the backend test suite."""

from pathlib import Path

import pytest
from django.conf import settings

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _data_dirs(tmp_path, settings, monkeypatch):
    """Each test gets fresh sample storage, rules and work dirs, eager tasks and an empty throttle cache.

    pytest-django keeps each test inside one transaction, which never commits, so `on_commit` callbacks would
    never run. Running them immediately models the commit the production code is waiting for.
    """
    from django.core.cache import cache
    from django.db import transaction

    from sentinel.celery import app as celery_app

    cache.clear()
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None: func())
    settings.SENTINEL = dict(settings.SENTINEL)
    settings.SENTINEL["DATA_DIR"] = tmp_path
    settings.SENTINEL["MEDIA_SAMPLES"] = tmp_path / "samples"
    settings.SENTINEL["WORK_DIR"] = tmp_path / "work"
    settings.SENTINEL["RULES_DIR"] = tmp_path / "rules"
    settings.SENTINEL["REPUTATION_DIR"] = tmp_path / "reputation"
    (tmp_path / "reputation").mkdir(parents=True, exist_ok=True)
    for name in ("bad_sha256.txt", "good_sha256.txt", "bad_signers.txt"):
        (tmp_path / "reputation" / name).write_text("", encoding="utf-8")
    yield


@pytest.fixture
def fixture_apk():
    """The harmless exp_plain fixture (built from android/fixture). Skips the test if it has not been built."""
    path = FIXTURE_DIR / "exp_plain.apk"
    if not path.exists():
        pytest.skip("exp_plain.apk fixture not built yet (see android/fixture)")
    return path


@pytest.fixture
def client():
    """DRF's client shadows pytest-django's: it supports credentials() and format="json"."""
    from rest_framework.test import APIClient

    return APIClient()


@pytest.fixture
def device(db):
    from devices.auth import hash_token, new_token
    from devices.models import Device

    token = new_token()
    dev = Device.objects.create(name="test phone", token_hash=hash_token(token))
    dev.raw_token = token
    return dev


@pytest.fixture
def device_client(device):
    from rest_framework.test import APIClient

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Device {device.raw_token}")
    return client


@pytest.fixture
def analyst(db):
    from django.contrib.auth.models import Group, User

    user = User.objects.create_user("analyst1", password="pw-analyst-1")
    group, _ = Group.objects.get_or_create(name="analyst")
    user.groups.add(group)
    return user


@pytest.fixture
def viewer(db):
    from django.contrib.auth.models import User

    return User.objects.create_user("viewer1", password="pw-viewer-1")


@pytest.fixture
def analyst_client(analyst):
    from rest_framework.test import APIClient

    client = APIClient()
    client.force_login(analyst)
    return client


@pytest.fixture
def viewer_client(viewer):
    from rest_framework.test import APIClient

    client = APIClient()
    client.force_login(viewer)
    return client


def make_zip_bytes(extra: dict | None = None) -> bytes:
    """A small, valid zip with the PK magic. Not a real APK: analysis records partial reasons, which is itself a path to test."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("assets/readme.txt", "hello")
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def sha256_of(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def register_device_via_api(client) -> dict:
    from devices.pairing import create_pairing_code

    code = create_pairing_code()
    resp = client.post("/api/v1/devices/register", {"pairing_code": code.code, "device_name": "Pixel test",
                                                    "android_version": "14", "app_version": "0.1.0"},
                       format="json")
    assert resp.status_code == 201, resp.content
    return resp.json()


def submission_payload(data: bytes, package="com.demo.expfixture", **extra) -> dict:
    body = {
        "package_name": package, "app_label": "Exp Fixture", "version_name": "1.0", "version_code": 1,
        "installer_package": None, "first_install_time": "2026-10-05T09:30:00Z",
        "requested_permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"],
        "apk_sha256": sha256_of(data), "apk_size_bytes": len(data), "split_count": 0,
    }
    body.update(extra)
    return body


__all__ = ["make_zip_bytes", "sha256_of", "register_device_via_api", "submission_payload", "settings", "FIXTURE_DIR"]
