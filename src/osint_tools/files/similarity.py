from __future__ import annotations

import hashlib

ALGORITHM = "simhash64-v1"
IMPLEMENTATION_VERSION = "1"


def fingerprint(data: bytes) -> str:
    """64-bit SimHash over bounded byte 4-grams; Hamming distance is native."""
    if not data:
        return "0000000000000000"
    width = min(4, len(data)); vector = [0] * 64
    available = len(data) - width + 1
    step = max(1, (available + 65535) // 65536)
    for offset in range(0, available, step):
        value = int.from_bytes(hashlib.blake2b(data[offset:offset + width], digest_size=8).digest(), "big")
        for bit in range(64): vector[bit] += 1 if value & (1 << bit) else -1
    result = sum((1 << bit) for bit, weight in enumerate(vector) if weight >= 0)
    return f"{result:016x}"


def distance(left: str, right: str) -> int:
    return (int(left, 16) ^ int(right, 16)).bit_count()
