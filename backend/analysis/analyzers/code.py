"""DexCodeAnalyzer (source=code), Stage 3 section 4.3.

Reads each classes*.dex string pool and class table (no execution). An API pattern counts as present when both
its class descriptor and its member name appear in the pool, which is how DEX references them.
"""
from __future__ import annotations

import json
from pathlib import Path

from analysis.context import AnalysisContext, Analyzer, AnalyzerResult
from analysis.dexfile import DexError, parse_dex

from .apk_meta import load_apk

API_FILE = Path(__file__).resolve().parent.parent / "data" / "api_signatures.json"
FRAMEWORK_PREFIXES = ("Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Lcom/google/", "Lokhttp3/",
                      "Ljava/", "Ljavax/", "Lorg/apache/")
REFLECTION_NAMES = {"invoke", "getMethod", "getDeclaredMethod", "forName"}
METHOD_BUDGET = 150_000


def load_api_patterns() -> dict[str, list[str]]:
    return json.loads(API_FILE.read_text(encoding="utf-8"))["categories"]


def dex_blobs(ctx: AnalysisContext) -> list[bytes]:
    if "dex_blobs" not in ctx.cache:
        apk = load_apk(ctx)
        ctx.cache["dex_blobs"] = [bytes(b) for b in apk.get_all_dex()]
    return ctx.cache["dex_blobs"]


def dex_infos(ctx: AnalysisContext):
    """Parsed dex files, cached for every analyzer that needs them. Unparseable dex is recorded, not fatal."""
    if "dex_infos" not in ctx.cache:
        infos, failures = [], []
        for idx, blob in enumerate(dex_blobs(ctx), start=1):
            try:
                infos.append(parse_dex(blob))
            except DexError as exc:
                failures.append(f"classes{idx if idx > 1 else ''}.dex: {exc}")
        ctx.cache["dex_infos"] = infos
        ctx.cache["dex_failures"] = failures
    return ctx.cache["dex_infos"]


def _simple_name(descriptor: str) -> str:
    inner = descriptor.rstrip(";").rsplit("/", 1)[-1]
    return inner.split("$", 1)[0]


class DexCodeAnalyzer(Analyzer):
    name = "code"
    source = "code"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        infos = dex_infos(ctx)
        failures = ctx.cache.get("dex_failures", [])
        if not infos:
            if failures:
                ctx.partial_reasons.append("code: dex parse failed")
            return AnalyzerResult({"dex_count": 0, "class_count": 0, "method_count": 0,
                                   "short_name_ratio": 0.0, "categories": {}, "api_hits": [],
                                   "reflection_refs": 0, "dynamic_loading": False, "truncated": False})
        pool: set[str] = set()
        descriptors: list[str] = []
        methods = classes = 0
        for info in infos:
            pool.update(info.strings)
            descriptors.extend(info.class_descriptors)
            methods += info.method_count
            classes += info.class_count
        truncated = methods > METHOD_BUDGET
        if truncated:
            ctx.partial_reasons.append("code: method budget exceeded (truncated)")

        app_classes = [d for d in descriptors if not d.startswith(FRAMEWORK_PREFIXES)]
        names = [_simple_name(d) for d in app_classes]
        short = sum(1 for n in names if len(n) <= 2)
        ratio = round(short / len(names), 3) if names else 0.0

        categories: dict[str, int] = {}
        hits = []
        for cat, patterns in load_api_patterns().items():
            for pattern in patterns:
                if _present(pattern, pool):
                    categories[cat] = categories.get(cat, 0) + 1
                    hits.append({"api": pattern, "category": cat})
        reflection = sum(1 for s in REFLECTION_NAMES if s in pool)
        return AnalyzerResult({
            "dex_count": len(infos), "class_count": classes, "method_count": methods,
            "app_class_count": len(names), "short_name_ratio": ratio,
            "categories": categories, "api_hits": hits[:100], "reflection_refs": reflection,
            "dynamic_loading": categories.get("dynamic_loading", 0) > 0, "truncated": truncated,
        })


def _present(pattern: str, pool: set[str]) -> bool:
    if "->" in pattern:
        cls, member = pattern.split("->", 1)
        return cls in pool and member in pool
    return pattern in pool
