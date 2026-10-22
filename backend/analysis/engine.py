"""Static analysis engine: Phases 0-3 of Stage 3 architecture section 2. Returns one Evidence dict."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from django.conf import settings
from jsonschema import Draft202012Validator
from loguru import logger as _androguard_logger

from .analyzers.apk_meta import ManifestAnalyzer, SigningAnalyzer
from .analyzers.code import DexCodeAnalyzer
from .analyzers.files import FilesEntropyAnalyzer, NativeLibsAnalyzer
from .analyzers.reputation import ReputationAnalyzer, YaraAnalyzer
from .analyzers.strings_iocs import StringsIocAnalyzer
from .context import AnalysisContext, run_analyzers
from .safe_zip import open_safely
from .signals import build_signals

SCHEMA_PATH = settings.BASE_DIR.parent / "shared" / "evidence.schema.json"

# androguard logs every parser step at DEBUG through loguru; keep only its warnings.
_androguard_logger.remove()
_androguard_logger.add(sys.stderr, level="WARNING")


class EvidenceInvalid(Exception):
    """Stage 3 section 6: a schema failure is a bug and sets status=error, error_code=evidence_invalid."""


def new_context(sha256: str, apk_path: str, workdir: str, meta: dict, emit) -> AnalysisContext:
    return AnalysisContext(sample_sha256=sha256, apk_path=apk_path, workdir=workdir,
                           submission_meta=meta, emit=emit,
                           budget_seconds=30)


def analyzers():
    return [ManifestAnalyzer(), SigningAnalyzer(), DexCodeAnalyzer(), NativeLibsAnalyzer(),
            FilesEntropyAnalyzer(), StringsIocAnalyzer(), ReputationAnalyzer(), YaraAnalyzer()]


def run_static(ctx: AnalysisContext) -> dict:
    report = open_safely(ctx.apk_path)
    ctx.cache["zip"] = report.zf
    ctx.signal_codes.extend(report.signals)
    ctx.partial_reasons.extend(report.partial_reasons)
    if report.unsafe_names:
        ctx.emit("static_analysis", "intake_warning",
                 f"{len(report.unsafe_names)} path-traversal entries skipped", "warn",
                 {"count": len(report.unsafe_names)})
    if report.zf is None:
        ctx.emit("static_analysis", "analyzer_finished", "Package could not be read safely", "warn", {})
    else:
        ctx.emit("static_analysis", "started", "Archive opened", "info", {"entries": len(report.entries)})

    run_analyzers(analyzers(), ctx)

    f = ctx.features
    rep = f.setdefault("reputation", {})
    rep["yara_hits"] = f.get("yara", {}).get("yara_hits", [])
    signals = build_signals({k: v for k, v in f.items() if k != "yara"},
                            intake={"signal_codes": ctx.signal_codes})
    evidence = {
        "schema_version": "1.0",
        "sample_sha256": ctx.sample_sha256,
        "analysis_version": settings.SENTINEL["ANALYSIS_VERSION"],
        "static": {
            "manifest": f.get("manifest", {}), "signing": f.get("signing", {}), "code": f.get("code", {}),
            "files": f.get("files", {}), "strings": f.get("strings", {}), "native": f.get("native", {}),
        },
        "dynamic": None,
        "reputation": {
            "bad_hash_hit": rep.get("bad_hash_hit", False), "good_hash_hit": rep.get("good_hash_hit", False),
            "bad_signer_hit": rep.get("bad_signer_hit", False), "yara_hits": rep.get("yara_hits", []),
        },
        "signals": signals,
        "partial": bool(ctx.partial_reasons),
        "partial_reasons": ctx.partial_reasons,
    }
    if report.zf is not None:
        report.zf.close()
    validate_evidence(evidence)
    return evidence


def validate_evidence(evidence: dict) -> None:
    schema = json.loads(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(evidence), key=lambda e: list(e.path))
    if errors:
        raise EvidenceInvalid("; ".join(e.message for e in errors[:3]))
