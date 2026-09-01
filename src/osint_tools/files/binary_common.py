from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryLimits:
    max_scan_bytes: int = 16 * 1024 * 1024
    max_strings: int = 2000
    min_string_length: int = 4
    max_string_length: int = 1024
    max_sections: int = 256
    max_symbols: int = 2000
    max_imports: int = 1000
    max_exports: int = 1000
    max_candidates: int = 500


def entropy(data: bytes) -> float:
    if not data: return 0.0
    size = len(data)
    return round(-sum((count / size) * math.log2(count / size) for count in Counter(data).values()), 6)


def extract_strings(data: bytes, limits: BinaryLimits) -> tuple[list[dict], bool]:
    values = []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % limits.min_string_length)
    for match in pattern.finditer(data):
        raw = match.group(); truncated = len(raw) > limits.max_string_length
        values.append({"value": raw[:limits.max_string_length].decode("ascii"), "encoding": "ascii", "offset": match.start(), "truncated": truncated})
        if len(values) >= limits.max_strings: return values, True
    wide = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % limits.min_string_length)
    for match in wide.finditer(data):
        raw = match.group(); maximum = limits.max_string_length * 2; truncated = len(raw) > maximum
        values.append({"value": raw[:maximum].decode("utf-16le", "ignore"), "encoding": "utf-16le", "offset": match.start(), "truncated": truncated})
        if len(values) >= limits.max_strings: return values, True
    values.sort(key=lambda item: item["offset"])
    return values, False
