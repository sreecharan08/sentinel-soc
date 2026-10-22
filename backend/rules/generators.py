"""Rule generation (Stage 6 section 5). Precision over recall: a noisy rule teaches evaluators to distrust the system.

generate_for(submission) runs after a malicious verdict (post_verdict). Every draft carries its self-test and
false-positive test results. Nothing becomes active until an analyst approves it (rules/services.py).
"""
from __future__ import annotations

import hashlib
import math
import re
import uuid
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path

import yaml
from django.conf import settings

from analysis.models import Analysis
from pipeline.events import emit
from submissions.services import current_verdict, effective_label

from .models import GeneratedRule
from .sigma import LOGSOURCE

GENERATOR = "sentinel-soc rulegen 0.1"
DENY_PREFIXES = ("android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "com.google.", "okhttp3.",
                 "org.apache.")
OBFUSCATED_CLASS = re.compile(r"^[a-z]{1,2}(\.[a-z]{1,2})*$")
DEX_MAGIC_UINT32 = "0x0a786564"    # little-endian uint32 of b"dex\n"
ALLOW_FILE = Path(__file__).resolve().parent.parent / "analysis" / "data" / "allowlists" / "domains.txt"


def _slug(package: str) -> str:
    last = re.sub(r"[^A-Za-z0-9]", "_", package.split(".")[-1]).strip("_").upper()
    return (last or "APP")[:24]


def _escape(text: str) -> str:
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) > 0x7E:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _entropy(text: str) -> float:
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0


def _allowed_domains() -> set[str]:
    return {line.strip().lower() for line in ALLOW_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


def _benign_index() -> set[str] | None:
    path = settings.SENTINEL["RULES_DIR"] / "benign_strings.sha1"
    if not path.exists():
        return None
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def candidates(evidence: dict, allow: set[str]) -> dict[int, list[str]]:
    """Priority 1: URLs, domains, public IPs. 2: app class names, embedded payload paths. 3: risky API names."""
    static = evidence.get("static", {})
    p1 = list(static.get("strings", {}).get("urls", []))
    p1 += [d for d in static.get("strings", {}).get("domains", [])
           if not any(d == a or d.endswith("." + a) for a in allow)]
    p1 += static.get("strings", {}).get("ips", [])
    p2 = []
    comps = static.get("manifest", {}).get("components", {})
    for bucket in comps.values():
        for name in bucket:
            descriptor = "L" + name.replace(".", "/") + ";"
            simple = name.rsplit(".", 1)[-1]
            if len(simple) >= 8 and not OBFUSCATED_CLASS.match(name):
                p2.append(descriptor)
    p2 += [e["path"] for e in static.get("files", {}).get("embedded_executables", [])]
    p3 = [h["api"] for h in static.get("code", {}).get("api_hits", [])
          if h.get("category") in ("dynamic_loading", "sms_send")]
    return {1: p1, 2: p2, 3: p3}


def select_strings(evidence: dict, benign: set[str] | None) -> tuple[list[tuple[int, str]], str | None]:
    allow = _allowed_domains()
    cands = candidates(evidence, allow)
    chosen: list[tuple[int, str]] = []
    seen = set()

    def acceptable(s: str) -> bool:
        if len(s) < 8 or _entropy(s) < 2.0 or any(s.startswith(p) for p in DENY_PREFIXES):
            return False
        if benign is not None and hashlib.sha1(s.encode("utf-8")).hexdigest() in benign:
            return False
        return s not in seen

    for prio, cap in ((1, 3), (2, 3)):
        for s in cands[prio]:
            if sum(1 for p, _ in chosen if p == prio) >= cap:
                break
            if acceptable(s):
                seen.add(s)
                chosen.append((prio, s))
    if len(chosen) < 2:  # API names only ever support a rule; they never make one on their own
        for s in cands[3]:
            if acceptable(s) and len(chosen) < 6:
                seen.add(s)
                chosen.append((3, s))
    specific = [c for c in chosen if c[0] in (1, 2)]
    if len(specific) < 2 and not any(p == 1 for p, _ in chosen):
        return [], "not enough specific strings"
    if len(chosen) > 6:
        chosen = chosen[:6]
    return chosen, None


def build_yara(name: str, sha256: str, verdict_id: int | None, level: str, chosen, confidence: float) -> str:
    net, cls, api = [], [], []
    for prio, s in chosen:
        if s.startswith("http") or prio == 1:
            net.append(s)
        elif s.startswith("L") and s.endswith(";"):
            cls.append(s)
        elif prio == 3:
            api.append(s)
        else:
            cls.append(s)
    strings = []
    for i, s in enumerate(net):
        strings.append(f'        $net{i} = "{_escape(s)}" ascii')
    for i, s in enumerate(cls):
        strings.append(f'        $cls{i} = "{_escape(s)}" ascii')
    for i, s in enumerate(api):
        strings.append(f'        $api{i} = "{_escape(s)}" ascii')
    conds = []
    if net:
        conds.append("any of ($net*)")
    # YARA rejects references to string sets that were never declared, so only name the ones present.
    sets = [name for name, items in (("$cls*", cls), ("$api*", api)) if items]
    if len(cls) + len(api) >= 2:
        conds.append(f"2 of ({', '.join(sets)})")
    condition = f"uint32(0) == {DEX_MAGIC_UINT32} and ({' or '.join(conds)})"
    lines = [
        f"rule {name} {{",
        "    meta:",
        f'        description = "Generated from verdict on sample {sha256[:12]}"',
        f'        sha256 = "{sha256}"',
        f'        generated_by = "{GENERATOR}"',
        f'        date = "{date.today().isoformat()}"',
        f'        confidence = "{confidence:.2f}"',
        f'        verdict_id = "{verdict_id or ""}"',
        '        reviewed = "false"',
        f'        severity = "{level}"',
        "    strings:",
        *strings,
        "    condition:",
        f"        {condition}",
        "}",
        "",
    ]
    return "\n".join(lines)


def validate_yara_text(text: str) -> None:
    """Raises ApiError-compatible ValueError when the rule does not compile (T6-12 style escaping is tested here)."""
    import yara

    try:
        yara.compile(source=text)
    except yara.SyntaxError as exc:
        from sentinel.errors import ApiError

        raise ApiError("validation_error", f"YARA rule does not compile: {exc}", 400)


def dex_members(apk_path: str) -> list[bytes]:
    out = []
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            base = Path(info.filename).name
            if base.startswith("classes") and base.endswith(".dex") and info.file_size <= 100 * 1024 * 1024:
                out.append(zf.read(info))
    return out


def self_test_and_fp(rule_text: str, sample_path: str) -> dict:
    import yara

    compiled = yara.compile(source=rule_text)
    own = any(compiled.match(data=dex) for dex in dex_members(sample_path))
    corpus_dir = settings.SENTINEL["DATA_DIR"] / "corpus" / "benign"
    fp = {"status": "not_run", "corpus_size": 0, "hits": []}
    if corpus_dir.exists():
        apks = sorted(corpus_dir.glob("*.apk"))
        hits = []
        for apk in apks:
            try:
                if any(compiled.match(data=dex) for dex in dex_members(str(apk))):
                    hits.append(apk.name)
            except (zipfile.BadZipFile, OSError):
                continue
        fp = {"status": "passed" if not hits else "failed", "corpus_size": len(apks), "hits": hits}
    return {"self_test": own, "fp_test": fp}


def generate_yara(sub, evidence: dict, verdict, force: bool = False) -> GeneratedRule | None:
    sha = sub.sample.sha256
    if not force and GeneratedRule.objects.filter(kind="yara", source_sha256=sha).exclude(status="retired").exists():
        emit(sub, "rules", "skipped", "Rules already generated for this file", level="debug")
        return None
    benign = _benign_index()
    chosen, reason = select_strings(evidence, benign)
    if reason:
        emit(sub, "rules", "skipped", f"Rule not generated: {reason}", data={"reason": reason})
        return None
    level = "high" if verdict.label == "malicious" else "medium"
    name = f"SENTINEL_{_slug(sub.package_name)}_{sha[:8]}"
    text = build_yara(name, sha, verdict.id, level, chosen, verdict.confidence)
    try:
        test = self_test_and_fp(text, sub.sample.file_path)
    except Exception as exc:  # noqa: BLE001 - rule syntax errors are skips, not failures of the verdict
        emit(sub, "rules", "skipped", f"Rule did not compile: {exc}", level="warn")
        return None
    if not test["self_test"]:
        emit(sub, "rules", "skipped", "Self-test failed: the rule does not match its own sample", level="error")
        return None
    version = (GeneratedRule.objects.filter(name=name).order_by("-version").values_list("version", flat=True)
               .first() or 0) + 1
    rule = GeneratedRule.objects.create(
        kind="yara", name=name, content=text, status="draft", level=level, source_submission=sub,
        source_sha256=sha, verdict=verdict, version=version,
        meta={"generator": GENERATOR, "confidence": verdict.confidence, "sample_package": sub.package_name,
              "strings": [s for _, s in chosen], "benign_filter": benign is not None},
        fp_test={**test["fp_test"], "run_at": date.today().isoformat(), "self_test": True})
    emit(sub, "rules", "generated", f"YARA draft {name} generated (FP test: {test['fp_test']['status']})",
         data={"rule_id": str(rule.id), "fp_test": test["fp_test"]["status"]})
    return rule


def sigma_rules_for(sub, evidence: dict, verdict) -> list[tuple[str, str]]:
    """Two Sigma rules per Stage 6 section 5.3. Returns (name, yaml_text)."""
    sha = sub.sample.sha256
    slug = _slug(sub.package_name)
    out = []
    tags = [f"attack.{t.lower()}" for s in evidence.get("signals", []) for t in s.get("attck", [])]
    tags = sorted(set(tags))
    if verdict.label == "malicious":
        hash_rule = {
            "title": f"Known-bad install {sub.package_name}",
            "id": _uuid(sha + "hash"), "status": "experimental", "description": "APK hash of a malicious verdict",
            "author": GENERATOR, "date": date.today().isoformat(), "tags": tags,
            "logsource": dict(LOGSOURCE),
            "detection": {"selection": {"apk_sha256": sha}, "condition": "selection"},
            "falsepositives": ["None expected for this exact file"], "level": "high",
        }
        out.append((f"SENTINEL_SIGMA_{slug}_HASH_{sha[:8]}", yaml.safe_dump(hash_rule, sort_keys=False)))
    perms = []
    for s in evidence.get("signals", []):
        if s["severity"] in ("medium", "high", "critical") and s["detail"].startswith("Declares android.permission."):
            perms.append(s["detail"].replace("Declares ", ""))
    perms = sorted(set(perms))
    if len(perms) >= 2:
        perm_rule = {
            "title": f"Risky permission set on install of {sub.package_name}",
            "id": _uuid(sha + "perm"), "status": "experimental",
            "description": "Install declares several risky permissions outside the Play Store",
            "author": GENERATOR, "date": date.today().isoformat(), "tags": tags,
            "logsource": dict(LOGSOURCE),
            "detection": {"selection": {"requested_permissions|all": perms},
                          "filter_store": {"installer_package": ["com.android.vending"]},
                          "condition": "selection and not filter_store"},
            "falsepositives": ["Messaging, banking or accessibility apps that legitimately request these"],
            "level": "medium",
        }
        out.append((f"SENTINEL_SIGMA_{slug}_PERM_{sha[:8]}", yaml.safe_dump(perm_rule, sort_keys=False)))
    return out


def _uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "sentinel:" + seed))


def generate_sigma(sub, evidence: dict, verdict) -> list[GeneratedRule]:
    from .sigma import UnsupportedSigma, load

    created = []
    for name, text in sigma_rules_for(sub, evidence, verdict):
        if GeneratedRule.objects.filter(name=name).exclude(status="retired").exists():
            continue
        try:
            sigma = load(text)
        except UnsupportedSigma as exc:
            emit(sub, "rules", "skipped", f"Sigma rule {name} is not valid: {exc}", level="warn")
            continue
        rule = GeneratedRule.objects.create(
            kind="sigma", name=name, content=text, status="draft", level=sigma.level, source_submission=sub,
            source_sha256=sub.sample.sha256, verdict=verdict, version=1,
            meta={"generator": GENERATOR, "export_only": False, "title": sigma.title},
            fp_test={"status": "not_run"})
        created.append(rule)
        emit(sub, "rules", "generated", f"Sigma draft {name} generated", data={"rule_id": str(rule.id)})
    return created


def generate_for(sub, force: bool = False) -> list[GeneratedRule]:
    verdict = current_verdict(sub)
    if verdict is None:
        return []
    label = effective_label(sub) or verdict.label
    if label != "malicious" and not force:
        emit(sub, "rules", "skipped", "Rules are generated for malicious verdicts or on analyst request",
             level="debug", data={"label": label})
        return []
    analysis = Analysis.objects.filter(sample=sub.sample, analysis_version=settings.SENTINEL["ANALYSIS_VERSION"]).first()
    if analysis is None:
        return []
    evidence = analysis.evidence
    created = []
    yara_rule = generate_yara(sub, evidence, verdict, force=force)
    if yara_rule is not None:
        created.append(yara_rule)
    created += generate_sigma(sub, evidence, verdict)
    from .services import match_approved_sigma

    match_approved_sigma(sub)
    return created


