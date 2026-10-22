"""Phase 0: zip validation and bounded reads (Stage 3 architecture section 8, safe_extract.py).

Nothing from the APK is written to disk here. Entries are read through bounded streams so a hostile archive
cannot exhaust memory, and path-traversal names are recorded and skipped.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass, field

MAX_ENTRIES = 20_000
MAX_TOTAL_UNCOMPRESSED = 1024 * 1024 * 1024       # 1 GB
MAX_RATIO = 200
RATIO_MIN_SIZE = 10 * 1024 * 1024                  # only judge the ratio for entries over 10 MB


@dataclass
class ZipReport:
    zf: zipfile.ZipFile | None
    signals: list[str] = field(default_factory=list)   # signal codes raised during intake
    unsafe_names: list[str] = field(default_factory=list)
    partial_reasons: list[str] = field(default_factory=list)
    entries: list[zipfile.ZipInfo] = field(default_factory=list)


def open_safely(path: str) -> ZipReport:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        return ZipReport(zf=None, signals=["SIG-FILE-900"], partial_reasons=[f"intake: not a readable zip ({exc})"])

    infos = zf.infolist()
    report = ZipReport(zf=zf, entries=infos)
    total = sum(i.file_size for i in infos)
    bomb = len(infos) > MAX_ENTRIES or total > MAX_TOTAL_UNCOMPRESSED or any(
        i.file_size > RATIO_MIN_SIZE and i.compress_size and i.file_size / max(i.compress_size, 1) > MAX_RATIO
        for i in infos)
    if bomb:
        report.signals.append("SIG-FILE-901")
        report.partial_reasons.append("intake: archive structure exceeds safe limits")
        report.entries = []
        return report
    for info in infos:
        name = info.filename
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/") or ":" in name.split("/")[0]:
            report.unsafe_names.append(name)
    if report.unsafe_names:
        report.signals.append("SIG-FILE-902")
    return report


def read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Read at most `limit` bytes of an entry. Never trusts the declared size alone."""
    with zf.open(info) as fh:
        return fh.read(limit)
