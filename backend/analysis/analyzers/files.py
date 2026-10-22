"""NativeLibsAnalyzer (source=files) and FilesEntropyAnalyzer (source=files). Stage 3 sections 4.4 and 4.5."""
from __future__ import annotations

import math
import os
from collections import Counter
from pathlib import Path

from analysis.context import AnalysisContext, Analyzer, AnalyzerResult
from analysis.safe_zip import read_bounded

PACKER_FILE = Path(__file__).resolve().parent.parent / "data" / "packer_libs.txt"
ENTROPY_SAMPLE = 1024 * 1024        # read up to 1 MB per blob
ENTROPY_THRESHOLD = 7.5
BLOB_MIN_SIZE = 50 * 1024
DEX_NAME = ("classes",)
MEDIA_EXTENSIONS = {".webp", ".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4", ".m4a", ".ogg", ".opus",
                    ".woff", ".woff2", ".ttf", ".otf", ".prof", ".ogv", ".wav"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _zip(ctx: AnalysisContext):
    zf = ctx.cache.get("zip")
    if zf is None:
        raise RuntimeError("archive not readable")
    return zf


def _is_dex_name(name: str) -> bool:
    base = os.path.basename(name)
    return base.startswith(DEX_NAME) and base.endswith(".dex")


class NativeLibsAnalyzer(Analyzer):
    name = "native"
    source = "files"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        packers = {line.strip() for line in PACKER_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}
        libs = []
        for info in _zip(ctx).infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                libs.append({"name": parts[2], "abi": parts[1], "size": info.file_size,
                             "packer_match": parts[2] in packers})
        return AnalyzerResult({"libs": libs[:200], "lib_count": len(libs)})


class FilesEntropyAnalyzer(Analyzer):
    name = "files"
    source = "files"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        zf = _zip(ctx)
        infos = zf.infolist()
        exts: Counter = Counter()
        executables, blobs = [], []
        for info in infos:
            name = info.filename
            ext = os.path.splitext(name)[1].lower() or "(none)"
            exts[ext] += 1
            if name.startswith("lib/") or _is_dex_name(name) or info.is_dir():
                continue
            head = read_bounded(zf, info, 8)
            kind = None
            if head.startswith(b"dex\n"):
                kind = "dex"
            elif head.startswith(b"\x7fELF"):
                kind = "elf"
            elif head.startswith(b"PK\x03\x04") and (name.startswith("assets/") or name.startswith("res/raw/")):
                kind = "nested_archive"
            if kind:
                executables.append({"path": name, "kind": kind, "size": info.file_size})
            # Compressed media is high-entropy by design; it says nothing about hidden payloads.
            if os.path.splitext(name)[1].lower() in MEDIA_EXTENSIONS:
                continue
            if (name.startswith("assets/") or name.startswith("res/raw/")) and info.file_size >= BLOB_MIN_SIZE:
                sample = read_bounded(zf, info, ENTROPY_SAMPLE)
                entropy = shannon_entropy(sample)
                if entropy > ENTROPY_THRESHOLD:
                    blobs.append({"path": name, "size": info.file_size, "entropy": round(entropy, 3)})
        return AnalyzerResult({
            "total_files": len(infos),
            "total_uncompressed": sum(i.file_size for i in infos),
            "top_extensions": dict(exts.most_common(10)),
            "embedded_executables": executables[:100],
            "high_entropy_blobs": blobs[:100],
        })
