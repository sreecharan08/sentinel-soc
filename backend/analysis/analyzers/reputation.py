"""ReputationAnalyzer and YaraAnalyzer (source=reputation). Stage 3 sections 4.7 and 4.8.

Reputation lists are plain text files read on every run, so analyst additions apply immediately.
YARA rules are compiled per file; a broken file is skipped with a partial reason naming it.
"""
from __future__ import annotations

from django.conf import settings

from analysis.context import AnalysisContext, Analyzer, AnalyzerResult
from analysis.safe_zip import read_bounded

from .code import dex_blobs

YARA_SCAN_LIMIT = 5 * 1024 * 1024
_compiled_cache: dict = {"key": None, "rules": None, "errors": []}


def _list(name: str) -> set[str]:
    path = settings.SENTINEL["REPUTATION_DIR"] / name
    if not path.exists():
        return set()
    return {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


def compile_rules() -> tuple[object | None, list[str]]:
    """Compile every approved YARA file in RULES_DIR/active/yara. Cached by the directory's file set and mtimes."""
    import yara

    rules_dir = settings.SENTINEL["RULES_DIR"] / "active" / "yara"
    files = sorted(rules_dir.glob("*.yar")) if rules_dir.exists() else []
    key = tuple((str(f), f.stat().st_mtime_ns) for f in files)
    if _compiled_cache["key"] == key:
        return _compiled_cache["rules"], _compiled_cache["errors"]
    ok, errors = {}, []
    for path in files:
        try:
            yara.compile(filepath=str(path))  # validate this file alone so one bad rule cannot break the rest
            ok[path.name] = str(path)
        except yara.Error as exc:
            errors.append(f"yara: {path.name} ({exc})")
    compiled = yara.compile(filepaths=ok) if ok else None
    _compiled_cache.update(key=key, rules=compiled, errors=errors)
    return compiled, errors


class ReputationAnalyzer(Analyzer):
    name = "reputation"
    source = "reputation"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        sha = ctx.sample_sha256
        signer = (ctx.features.get("signing") or {}).get("cert_sha256")
        return AnalyzerResult({
            "bad_hash_hit": sha in _list("bad_sha256.txt"),
            "good_hash_hit": sha in _list("good_sha256.txt"),
            "bad_signer_hit": bool(signer) and signer.lower() in _list("bad_signers.txt"),
            "yara_hits": [],   # filled by YaraAnalyzer and merged by the engine
        })


class YaraAnalyzer(Analyzer):
    name = "yara"
    source = "reputation"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        rules, errors = compile_rules()
        ctx.partial_reasons.extend(errors)
        if rules is None:
            return AnalyzerResult({"yara_hits": [], "rules_loaded": 0})
        hits = []
        for idx, blob in enumerate(dex_blobs(ctx), start=1):
            hits.extend(_scan(rules, blob, f"classes{'' if idx == 1 else idx}.dex"))
        manifest = ctx.cache.get("manifest_xml")
        if manifest:
            hits.extend(_scan(rules, manifest, "AndroidManifest.xml"))
        zf = ctx.cache.get("zip")
        if zf is not None:
            for info in zf.infolist():
                if info.filename.startswith("assets/") and info.file_size <= YARA_SCAN_LIMIT:
                    hits.extend(_scan(rules, read_bounded(zf, info, YARA_SCAN_LIMIT), info.filename))
        seen, unique = set(), []
        for h in hits:
            key = (h["rule"], h["file"])
            if key not in seen:
                seen.add(key)
                unique.append(h)
        return AnalyzerResult({"yara_hits": unique[:100], "rules_loaded": len(rules) if hasattr(rules, "__len__") else 1})


def _scan(rules, data: bytes, label: str) -> list[dict]:
    out = []
    for match in rules.match(data=data):
        meta = dict(match.meta or {})
        out.append({"rule": match.rule, "file": label, "severity": meta.get("severity", "medium"),
                    "tags": list(match.tags or [])})
    return out
