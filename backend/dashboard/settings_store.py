"""Read/write runtime settings. A SiteSetting row overrides the environment default (CONTRACTS section 11)."""
from __future__ import annotations

from django.conf import settings
from django.utils import timezone

from pipeline.events import emit

from .models import SiteSetting

ALLOWED = {
    "auto_remediation_enabled": bool,
    "auto_remediation_min_confidence": float,
    "remediation_rate_limit_per_device_hour": int,
    "protected_packages": list,
    "reasoner_backend": str,
    "dynamic_enabled": bool,
    "show_demo_console": bool,
    "fault": (str, type(None)),
}


def _env_defaults() -> dict:
    s = settings.SENTINEL
    return {
        "auto_remediation_enabled": s["AUTO_REMEDIATION_ENABLED"],
        "auto_remediation_min_confidence": s["AUTO_REMEDIATION_MIN_CONFIDENCE"],
        "remediation_rate_limit_per_device_hour": s["REMEDIATION_RATE_LIMIT_PER_DEVICE_HOUR"],
        "protected_packages": [],
        "reasoner_backend": s["REASONER_BACKEND"],
        "dynamic_enabled": s["DYNAMIC_ENABLED"],
        "show_demo_console": False,
        "fault": None,
    }


def get_setting(key: str, default=None):
    row = SiteSetting.objects.filter(key=key).first()
    if row is not None:
        return row.value.get("v")
    return default if default is not None else _env_defaults().get(key)


def effective_settings() -> dict:
    cfg = _env_defaults()
    for row in SiteSetting.objects.all():
        cfg[row.key] = row.value.get("v")
    cfg["own_package"] = "com.sentinel.soc"
    return cfg


def set_setting(key: str, value, user) -> dict:
    """Validates, stores, and records the change as a `system/settings_changed` event."""
    if key not in ALLOWED:
        raise KeyError(key)
    expected = ALLOWED[key]
    if not isinstance(value, expected) or (expected is float and isinstance(value, bool)):
        raise ValueError(f"{key} must be {getattr(expected, '__name__', expected)}")
    if key == "auto_remediation_min_confidence" and not 0.5 <= value <= 0.99:
        raise ValueError("auto_remediation_min_confidence must be between 0.5 and 0.99")
    if key == "remediation_rate_limit_per_device_hour" and not 1 <= value <= 100:
        raise ValueError("rate limit must be between 1 and 100")
    if key == "reasoner_backend" and value not in ("rules", "hybrid"):
        raise ValueError("reasoner_backend must be 'rules' or 'hybrid'")
    old = get_setting(key)
    SiteSetting.objects.update_or_create(key=key, defaults={"value": {"v": value}, "updated_by": user,
                                                             "updated_at": timezone.now()})
    emit(None, "system", "settings_changed", f"Setting {key} changed",
         data={"key": key, "old": old, "new": value, "user": user.get_username() if user else None})
    return {"key": key, "value": value}
