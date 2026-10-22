"""ManifestAnalyzer (source=manifest) and SigningAnalyzer (source=signing). Stage 3 section 4.1 and 4.2."""
from __future__ import annotations

import hashlib
from datetime import timezone
from pathlib import Path

from lxml import etree

from analysis.context import AnalysisContext, Analyzer, AnalyzerResult

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
NOTABLE_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED": "BOOT_COMPLETED",
    "android.provider.Telephony.SMS_RECEIVED": "SMS_RECEIVED",
    "android.intent.action.PACKAGE_ADDED": "PACKAGE_ADDED",
    "android.intent.action.NEW_OUTGOING_CALL": "NEW_OUTGOING_CALL",
}
DANGEROUS_FILE = Path(__file__).resolve().parent.parent / "data" / "dangerous_permissions.txt"


def load_apk(ctx: AnalysisContext):
    """One parsed APK object per run, shared by the manifest and signing analyzers."""
    if "apk" not in ctx.cache:
        from androguard.core.apk import APK

        ctx.cache["apk"] = APK(ctx.apk_path)
    return ctx.cache["apk"]


def _dangerous() -> set[str]:
    return {line.strip() for line in DANGEROUS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}


def _attr(el, name: str, default=None):
    return el.get(ANDROID_NS + name, default)


def _qualify(name: str | None, package: str) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


def _intent_actions(el) -> set[str]:
    out = set()
    for flt in el.findall("intent-filter"):
        for action in flt.findall("action"):
            out.add(_attr(action, "name", ""))
    return out


def _intent_categories(el) -> set[str]:
    out = set()
    for flt in el.findall("intent-filter"):
        for cat in flt.findall("category"):
            out.add(_attr(cat, "name", ""))
    return out


class ManifestAnalyzer(Analyzer):
    name = "manifest"
    source = "manifest"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        try:
            apk = load_apk(ctx)
            root = apk.get_android_manifest_xml()
        except Exception as exc:  # noqa: BLE001
            ctx.partial_reasons.append(f"manifest: {exc}")
            perms = sorted(set(ctx.submission_meta.get("requested_permissions", [])))
            return AnalyzerResult({
                "source": "phone_reported", "package": ctx.submission_meta.get("package_name", ""),
                "permissions": perms, "dangerous_permissions": sorted(set(perms) & _dangerous()),
                "components": {}, "exported_components": [], "accessibility_services": [],
                "device_admin_receivers": [], "notable_intent_filters": [], "has_launcher_activity": None,
                "debuggable": False,
            })

        package = apk.get_package() or ""
        perms = sorted(set(apk.get_permissions() or []))
        app = root.find("application")
        target = int(apk.get_target_sdk_version() or 0)
        app_el = app if app is not None else root
        components = {"activities": [], "services": [], "receivers": [], "providers": []}
        exported, accessibility, admins, notable = [], [], [], set()
        has_launcher = False

        for tag, bucket in (("activity", "activities"), ("service", "services"),
                            ("receiver", "receivers"), ("provider", "providers")):
            for el in app_el.findall(tag):
                name = _qualify(_attr(el, "name"), package)
                components[bucket].append(name)
                explicit = _attr(el, "exported")
                has_filter = bool(el.findall("intent-filter"))
                is_exported = (explicit == "true") if explicit is not None else (has_filter and target < 31)
                permission = _attr(el, "permission")
                if is_exported:
                    exported.append({"name": name, "type": tag, "permission": permission})
                if tag == "service" and permission == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                    accessibility.append(name)
                if tag == "receiver" and permission == "android.permission.BIND_DEVICE_ADMIN":
                    admins.append(name)
                if tag == "activity" and {"android.intent.action.MAIN"} <= _intent_actions(el) \
                        and "android.intent.category.LAUNCHER" in _intent_categories(el):
                    has_launcher = True
            # Launchers are often declared as <activity-alias> (e.g. Signal); they count too.
            for alias in app_el.findall("activity-alias"):
                if {"android.intent.action.MAIN"} <= _intent_actions(alias) \
                        and "android.intent.category.LAUNCHER" in _intent_categories(alias):
                    has_launcher = True
                notable |= {NOTABLE_ACTIONS[a] for a in _intent_actions(el) if a in NOTABLE_ACTIONS}

        dangerous = sorted(set(perms) & _dangerous())
        custom = sorted(p for p in perms if not p.startswith("android.permission."))
        ctx.cache["manifest_xml"] = etree.tostring(root)
        return AnalyzerResult({
            "source": "apk", "package": package,
            "version_name": apk.get_androidversion_name() or "",
            "version_code": int(apk.get_androidversion_code() or 0),
            "min_sdk": int(apk.get_min_sdk_version() or 0), "target_sdk": target,
            "debuggable": _attr(app_el, "debuggable") == "true",
            "allow_backup": _attr(app_el, "allowBackup", "true") == "true",
            "permissions": perms, "dangerous_permissions": dangerous, "custom_permissions": custom,
            "components": components, "exported_components": exported,
            "accessibility_services": accessibility, "device_admin_receivers": admins,
            "notable_intent_filters": sorted(notable), "has_launcher_activity": has_launcher,
        })


class SigningAnalyzer(Analyzer):
    name = "signing"
    source = "signing"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        from cryptography import x509

        apk = load_apk(ctx)
        schemes = [s for s, ok in (("v1", apk.is_signed_v1()), ("v2", apk.is_signed_v2()),
                                   ("v3", apk.is_signed_v3())) if ok]
        ders = list(apk.get_certificates_der_v2() or []) or list(apk.get_certificates_der_v3() or [])
        certs = []
        for der in ders:
            cert = x509.load_der_x509_certificate(der)
            subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
            certs.append({
                "sha256": hashlib.sha256(der).hexdigest(), "subject": subject, "issuer": issuer,
                "not_before": cert.not_valid_before_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "not_after": cert.not_valid_after_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "serial": format(cert.serial_number, "x"),
            })
        first = certs[0] if certs else None
        return AnalyzerResult({
            "schemes": schemes, "certs": certs,
            "cert_sha256": first["sha256"] if first else None,
            "debug_cert": any("CN=Android Debug" in c["subject"] for c in certs),
            "self_signed": bool(first and first["subject"] == first["issuer"]),
        })
