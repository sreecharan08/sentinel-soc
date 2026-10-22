"""SignalEngine: features -> normalised, reasoner-facing signals (Stage 3 section 5, signal-catalog.md).

Each catalog row is one check that returns a list of detail strings (empty list = not triggered).
Severity labels live here; weights live in the reasoner (Stage 4 seam), not here.
Signal ids (`sig_N`) are assigned after sorting by severity then code, so they are stable for a given input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

SEVERITY_RANK = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
SOURCE_BY_PREFIX = {"PERM": "manifest", "MAN": "manifest", "SIGN": "signing", "CODE": "code",
                    "FILE": "files", "STR": "strings", "REP": "reputation", "DYN": "dynamic"}

Check = Callable[[dict, dict], list[str]]   # (features, intake) -> details


@dataclass(frozen=True)
class SignalRule:
    code: str
    name: str
    severity: str
    category: str
    check: Check
    attck: tuple[str, ...] = ()


def _perms(f: dict) -> set[str]:
    return set(f.get("manifest", {}).get("permissions", []))


def _has_perm(short: str) -> Check:
    full = f"android.permission.{short}"

    def check(f, _intake):
        return [f"Declares {full}"] if full in _perms(f) else []
    return check


def _cats(f: dict) -> dict:
    return f.get("code", {}).get("categories", {})


def _cat_count(category: str) -> Check:
    def check(f, _intake):
        n = _cats(f).get(category, 0)
        return [f"{category.replace('_', ' ')} references found: {n}"] if n else []
    return check


def _strings(f: dict) -> dict:
    return f.get("strings", {})


def _public_domains(f: dict) -> list[str]:
    return _strings(f).get("urls", [])


def _sms_perms(f, _i):
    return [f"Declares android.permission.{p}" for p in ("READ_SMS", "RECEIVE_SMS", "SEND_SMS") if
            f"android.permission.{p}" in _perms(f)]


def _contacts_calllog(f, _i):
    p = _perms(f)
    if "android.permission.READ_CONTACTS" in p and (
            "android.permission.READ_CALL_LOG" in p or "android.permission.WRITE_CONTACTS" in p):
        return ["Declares READ_CONTACTS together with call-log or contact-write access"]
    return []


def _accessibility(f, _i):
    return [f"Declares accessibility service {s}" for s in f.get("manifest", {}).get("accessibility_services", [])]


def _device_admin(f, _i):
    return [f"Declares device-admin receiver {r}" for r in f.get("manifest", {}).get("device_admin_receivers", [])]


def _many_dangerous(f, _i):
    n = len(f.get("manifest", {}).get("dangerous_permissions", []))
    return [f"{n} dangerous permissions declared"] if n >= 8 else []


def _debuggable(f, _i):
    return ["Build is debuggable (android:debuggable=true)"] if f.get("manifest", {}).get("debuggable") else []


def _exported_many(f, _i):
    exported = [c for c in f.get("manifest", {}).get("exported_components", []) if not c.get("permission")]
    return [f"{len(exported)} exported components without a permission guard"] if len(exported) >= 5 else []


def _no_launcher(f, _i):
    m = f.get("manifest", {})
    has_services = bool(m.get("components", {}).get("services") or m.get("components", {}).get("receivers"))
    return ["No launcher activity, but declares services or receivers"] if (
        m and not m.get("has_launcher_activity") and has_services) else []


IMPERSONATED = ("google", "android.system", "samsung", "whatsapp", "paypal", "microsoft")
LEGIT_PREFIX = ("com.google.", "com.samsung.", "com.whatsapp", "com.android.", "com.microsoft.", "com.paypal.")


def _imitation(f, _i):
    pkg = f.get("manifest", {}).get("package", "")
    if not pkg or pkg.startswith(LEGIT_PREFIX):
        return []
    hits = [t for t in IMPERSONATED if t in pkg.lower()]
    return [f"Package name {pkg} contains '{hits[0]}' but does not use its publisher's namespace"] if hits else []


def _old_target(f, _i):
    ts = f.get("manifest", {}).get("target_sdk")
    return [f"Targets API {ts}"] if isinstance(ts, int) and ts < 26 else []


def _debug_cert(f, _i):
    return ["Signed with the Android debug certificate"] if f.get("signing", {}).get("debug_cert") else []


def _legacy_only(f, _i):
    schemes = f.get("signing", {}).get("schemes", [])
    return ["Only the legacy v1 signature scheme is present"] if schemes == ["v1"] else []


def _bad_signer(f, _i):
    return ["Signing certificate appears on the known-bad list"] if f.get("reputation", {}).get("bad_signer_hit") else []


def _short_names(f, _i):
    ratio = f.get("code", {}).get("short_name_ratio", 0.0)
    return [f"{ratio:.0%} of app identifiers are two characters or fewer"] if ratio >= 0.6 else []


def _reflection(f, _i):
    n = f.get("code", {}).get("reflection_refs", 0)
    return [f"{n} reflection references"] if n >= 50 else []


def _decrypt_plus_blob(f, _i):
    decrypt = _cats(f).get("crypto_decrypt", 0)
    blobs = f.get("files", {}).get("high_entropy_blobs", [])
    return ["Decryption API present alongside a high-entropy embedded asset"] if decrypt and blobs else []


def _packer(f, _i):
    return [f"Packer library {lib['name']}" for lib in f.get("native", {}).get("libs", []) if lib.get("packer_match")]


def _embedded_exec(f, _i):
    return [f"Embedded {e['kind']} payload at {e['path']} ({e['size']} bytes)"
            for e in f.get("files", {}).get("embedded_executables", [])]


def _blobs(f, _i):
    return [f"High-entropy blob {b['path']} (entropy {b['entropy']:.2f}, {b['size']} bytes)"
            for b in f.get("files", {}).get("high_entropy_blobs", [])]


def _intake(code: str) -> Check:
    def check(_f, intake):
        return [f"Package could not be read safely ({code})"] if code in intake.get("signal_codes", []) else []
    return check


def _urls(f, _i):
    return [f"Hard-coded external URL: {u}" for u in _public_domains(f)[:5]]


def _public_ips(f, _i):
    return [f"Hard-coded public IP address {ip}" for ip in _strings(f).get("ips", [])[:5]]


def _flagged_hosts(f, _i):
    return [f"{h} ({kind})" for h, kind in _strings(f).get("flagged_hosts", {}).items()][:5]


def _telegram(f, _i):
    return ["Telegram bot API endpoint embedded"] if _strings(f).get("telegram_bot") else []


def _bad_hash(f, _i):
    return ["SHA-256 of this file is on the known-bad list"] if f.get("reputation", {}).get("bad_hash_hit") else []


def _good_hash(f, _i):
    return ["SHA-256 of this file is on the known-good list"] if f.get("reputation", {}).get("good_hash_hit") else []


def _yara(f, _i):
    return [f"Matched detection rule {h['rule']} in {h['file']}"
            for h in f.get("reputation", {}).get("yara_hits", [])]


CATALOG: list[SignalRule] = [
    # ---- manifest / permissions
    SignalRule("SIG-PERM-001", "SMS access", "high", "data_access", _sms_perms, ("T1636",)),
    SignalRule("SIG-PERM-002", "Contacts and call-log access", "medium", "data_access", _contacts_calllog, ("T1636",)),
    SignalRule("SIG-PERM-003", "Accessibility service declared", "high", "input_capture", _accessibility, ("T1417",)),
    SignalRule("SIG-PERM-004", "Draw over other apps", "medium", "input_capture", _has_perm("SYSTEM_ALERT_WINDOW"), ("T1417",)),
    SignalRule("SIG-PERM-005", "Can request package installs", "medium", "device_control", _has_perm("REQUEST_INSTALL_PACKAGES")),
    SignalRule("SIG-PERM-006", "Device-admin receiver", "high", "device_control", _device_admin),
    SignalRule("SIG-PERM-007", "Starts at boot", "low", "persistence", _has_perm("RECEIVE_BOOT_COMPLETED")),
    SignalRule("SIG-PERM-008", "Can list all installed apps", "low", "discovery", _has_perm("QUERY_ALL_PACKAGES"), ("T1418",)),
    SignalRule("SIG-PERM-009", "Many dangerous permissions", "medium", "data_access", _many_dangerous),
    SignalRule("SIG-PERM-010", "Background location", "medium", "location", _has_perm("ACCESS_BACKGROUND_LOCATION"), ("T1430",)),
    SignalRule("SIG-MAN-001", "Debuggable build", "medium", "build", _debuggable),
    SignalRule("SIG-MAN-002", "Many unprotected exported components", "low", "exposure", _exported_many),
    SignalRule("SIG-MAN-003", "No launcher activity", "medium", "masquerading", _no_launcher),
    SignalRule("SIG-MAN-004", "Name imitates a well-known publisher", "medium", "masquerading", _imitation, ("T1655",)),
    SignalRule("SIG-MAN-005", "Old target SDK", "low", "build", _old_target),
    # ---- signing
    SignalRule("SIG-SIGN-001", "Debug signing certificate", "medium", "integrity", _debug_cert),
    SignalRule("SIG-SIGN-002", "Only legacy v1 signature", "low", "integrity", _legacy_only),
    SignalRule("SIG-SIGN-003", "Signer seen on a known-bad sample", "critical", "integrity", _bad_signer),
    # ---- code
    SignalRule("SIG-CODE-001", "Loads code at runtime", "medium", "defense_evasion", _cat_count("dynamic_loading"), ("T1407",)),
    SignalRule("SIG-CODE-002", "Heavy reflection", "low", "defense_evasion", _reflection),
    SignalRule("SIG-CODE-003", "Runs shell commands", "medium", "execution", _cat_count("shell_exec")),
    SignalRule("SIG-CODE-004", "Sends SMS from code", "high", "data_access", _cat_count("sms_send")),
    SignalRule("SIG-CODE-005", "Installs other packages", "medium", "device_control", _cat_count("package_install")),
    SignalRule("SIG-CODE-006", "Decrypts embedded data", "low", "defense_evasion", _decrypt_plus_blob, ("T1406",)),
    SignalRule("SIG-CODE-007", "Known packer library", "medium", "defense_evasion", _packer, ("T1406",)),
    SignalRule("SIG-CODE-008", "Heavily renamed identifiers", "low", "defense_evasion", _short_names, ("T1406",)),
    SignalRule("SIG-CODE-009", "Performs gestures via accessibility", "high", "input_capture", _cat_count("accessibility_actions"), ("T1417",)),
    SignalRule("SIG-CODE-010", "Locks or wipes device", "high", "device_control", _cat_count("device_admin_actions")),
    # ---- files
    SignalRule("SIG-FILE-001", "Embedded executable payload", "high", "defense_evasion", _embedded_exec, ("T1407",)),
    SignalRule("SIG-FILE-002", "High-entropy blob", "medium", "defense_evasion", _blobs, ("T1406",)),
    SignalRule("SIG-FILE-900", "Unreadable package", "medium", "intake", _intake("SIG-FILE-900")),
    SignalRule("SIG-FILE-901", "Suspicious archive structure", "high", "intake", _intake("SIG-FILE-901")),
    SignalRule("SIG-FILE-902", "Path-traversal entry", "high", "intake", _intake("SIG-FILE-902")),
    # ---- strings / IOCs
    SignalRule("SIG-STR-001", "Hard-coded external URL", "medium", "network", _urls),
    SignalRule("SIG-STR-002", "Hard-coded public IP address", "medium", "network", _public_ips),
    SignalRule("SIG-STR-003", "Shortener, dynamic-DNS or paste host", "medium", "network", _flagged_hosts),
    SignalRule("SIG-STR-004", "Telegram bot API URL", "medium", "network", _telegram),
    # ---- reputation
    SignalRule("SIG-REP-001", "Known-bad file hash", "critical", "reputation", _bad_hash),
    SignalRule("SIG-REP-002", "Known-good file hash", "info", "reputation", _good_hash),
    SignalRule("SIG-REP-003", "Matched detection rule", "medium", "reputation", _yara),
]


def build_signals(features: dict, intake: dict | None = None) -> list[dict]:
    intake = intake or {}
    hits: list[tuple[SignalRule, str]] = []
    for rule in CATALOG:
        for detail in rule.check(features, intake):
            hits.append((rule, detail))
    hits.sort(key=lambda h: (SEVERITY_RANK[h[0].severity], h[0].code, h[1]))
    out = []
    for i, (rule, detail) in enumerate(hits, start=1):
        prefix = rule.code.split("-")[1]
        out.append({
            "id": f"sig_{i}", "code": rule.code, "name": rule.name, "severity": rule.severity,
            "category": rule.category, "source": SOURCE_BY_PREFIX.get(prefix, "manifest"),
            "detail": detail[:500], "attck": list(rule.attck),
        })
    return out
