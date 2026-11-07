"""Bloom-filter de-duplication of the discovery stream (requirement DA-15; spec p. 30, "Data streams are pushed
through an in-memory Bloom filter to quickly filter out duplicate entries before updating the persistence graph").

The filter lives in Redis short-term memory (asvas:st:<assessment>:bloom, erased with the run) so every orchestrator
shares it. A Bloom filter answers "definitely new" or "maybe seen":
* definitely new  -> write the record (no lookup needed);
* maybe seen      -> confirm with an exact lookup; only an exact duplicate is skipped.
So a false positive costs one lookup and never drops data.
"""

from __future__ import annotations

import hashlib
import math

import redis

M_BITS = 1 << 20      # 128 KiB per assessment
K_HASHES = 7          # ~1% false positives at ~110k entries


def _positions(item: str, m: int = M_BITS, k: int = K_HASHES) -> list[int]:
    d = hashlib.sha256(item.encode()).digest()
    h1, h2 = int.from_bytes(d[:8], "big"), int.from_bytes(d[8:16], "big") | 1
    return [(h1 + i * h2) % m for i in range(k)]


def false_positive_rate(n: int, m: int = M_BITS, k: int = K_HASHES) -> float:
    return (1 - math.exp(-k * n / m)) ** k


class BloomFilter:
    """Redis-bitmap Bloom filter. `add` returns True if the item was possibly present before (maybe seen)."""

    def __init__(self, r: redis.Redis, key: str, ttl_seconds: int):
        self.r, self.key, self.ttl = r, key, ttl_seconds

    def add(self, item: str) -> bool:
        pos = _positions(item)
        p = self.r.pipeline(transaction=True)
        for x in pos:
            p.setbit(self.key, x, 1)
        p.expire(self.key, self.ttl)
        old = p.execute()[:-1]
        return all(old)

    def __contains__(self, item: str) -> bool:
        p = self.r.pipeline(transaction=False)
        for x in _positions(item):
            p.getbit(self.key, x)
        return all(p.execute())


class LocalBloom:
    """Same semantics in process memory (used when no Redis is available, e.g. unit tests)."""

    def __init__(self, m: int = M_BITS):
        self.bits = bytearray(m // 8)
        self.m = m

    def add(self, item: str) -> bool:
        seen = True
        for x in _positions(item, self.m):
            b, bit = divmod(x, 8)
            if not self.bits[b] >> bit & 1:
                seen = False
                self.bits[b] |= 1 << bit
        return seen
