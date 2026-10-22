"""Minimal, dependency-free DEX reader: header counts, the string pool and class descriptors.

Reading the string pool (not running the code) is enough for API-reference detection, IOC extraction and
identifier-length statistics. It never executes anything in the sample (analysis-safety rule 1).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


class DexError(ValueError):
    pass


def _uleb128(data: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if off >= len(data):
            raise DexError("truncated uleb128")
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise DexError("uleb128 too long")


@dataclass
class DexInfo:
    strings: list[str] = field(default_factory=list)
    class_descriptors: list[str] = field(default_factory=list)  # e.g. "Lcom/demo/Foo;"
    method_count: int = 0
    class_count: int = 0


def parse_dex(data: bytes, max_strings: int = 400_000) -> DexInfo:
    if len(data) < 0x70 or data[:4] not in (b"dex\n",):
        raise DexError("not a dex file")
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
    (method_ids_size,) = struct.unpack_from("<I", data, 0x58)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)
    if string_ids_size > max_strings:
        raise DexError("string pool too large")

    strings: list[str] = []
    for i in range(string_ids_size):
        (str_off,) = struct.unpack_from("<I", data, string_ids_off + 4 * i)
        _, pos = _uleb128(data, str_off)          # utf16 length (we decode until the terminating NUL)
        end = data.index(b"\x00", pos)
        strings.append(data[pos:end].decode("utf-8", "replace"))

    type_strings = []
    for i in range(type_ids_size):
        (sidx,) = struct.unpack_from("<I", data, type_ids_off + 4 * i)
        type_strings.append(strings[sidx] if sidx < len(strings) else "")

    descriptors = []
    for i in range(class_defs_size):
        (class_idx,) = struct.unpack_from("<I", data, class_defs_off + 32 * i)
        if class_idx < len(type_strings):
            descriptors.append(type_strings[class_idx])

    return DexInfo(strings=strings, class_descriptors=descriptors, method_count=method_ids_size,
                   class_count=class_defs_size)
