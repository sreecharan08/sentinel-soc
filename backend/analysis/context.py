"""Analyzer plugin model (Stage 3 architecture section 3, analyzer_skeleton.py)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

Emit = Callable[..., None]   # emit(stage, step, message, level, data)


@dataclass
class AnalysisContext:
    sample_sha256: str
    apk_path: str
    workdir: str
    submission_meta: dict = field(default_factory=dict)
    budget_seconds: int = 30
    features: dict[str, Any] = field(default_factory=dict)
    partial_reasons: list[str] = field(default_factory=list)
    signal_codes: list[str] = field(default_factory=list)          # intake-level signals (SIG-FILE-9xx)
    cache: dict[str, Any] = field(default_factory=dict)            # parsed dex / zip shared by analyzers
    emit: Emit = lambda *a, **k: None


@dataclass
class AnalyzerResult:
    features: dict[str, Any]
    notes: list[str] = field(default_factory=list)


class Analyzer:
    name = "base"
    version = "1"
    source = "manifest"   # manifest|signing|code|files|strings|reputation|dynamic

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        raise NotImplementedError


def run_analyzers(analyzers: list[Analyzer], ctx: AnalysisContext) -> None:
    """Each analyzer is isolated: a failure becomes a partial reason, never an exception (Stage 3 section 3)."""
    for analyzer in analyzers:
        ctx.emit("static_analysis", "analyzer_started", f"{analyzer.name} started", "info", {"name": analyzer.name})
        started = time.monotonic()
        try:
            result = analyzer.run(ctx)
            ctx.features[analyzer.name] = result.features
            ms = int((time.monotonic() - started) * 1000)
            ctx.emit("static_analysis", "analyzer_finished", f"{analyzer.name} finished in {ms} ms", "info",
                     {"name": analyzer.name, "ms": ms, "keys": sorted(result.features)})
        except Exception as exc:  # noqa: BLE001 - deliberate: one analyzer must not sink the rest
            ctx.partial_reasons.append(f"{analyzer.name}: {exc}")
            ctx.features.setdefault(analyzer.name, {})
            ctx.emit("static_analysis", "analyzer_finished", f"{analyzer.name} failed: {exc}", "warn",
                     {"name": analyzer.name, "failed": True})
