"""Short-term (per-run) memory in Redis (requirements DA-05, PL-05; spec pp. 16, 49, 69, 73).

Everything lives under `asvas:st:<assessment id>:` with a TTL bounded by the assessment's wall-clock budget, and is
deleted when the assessment reaches a terminal state (engine._clear_short_term). Durable facts (jobs, evidence,
findings, audit) are in PostgreSQL; this holds only working state:

* consecutive failure counters per planning path (tool x service) and the set of blocked paths (PL-05);
* the planner's per-round working notes (accepted/rejected counts) for the next round's context.
"""

from __future__ import annotations

import json

import redis

FAILURE_THRESHOLD = 3  # spec p.49: three consecutive failures mark the path blocked


def prefix(assessment_id) -> str:
    return f"asvas:st:{assessment_id}:"


def _ttl(wall_clock_minutes: int) -> int:
    return wall_clock_minutes * 60 + 3600


def record_failure(r: redis.Redis, assessment_id, path: str, wall_clock_minutes: int) -> int:
    k = prefix(assessment_id) + "fail:" + path
    n = r.incr(k)
    r.expire(k, _ttl(wall_clock_minutes))
    return int(n)


def reset_failures(r: redis.Redis, assessment_id, path: str) -> None:
    r.delete(prefix(assessment_id) + "fail:" + path)


def block(r: redis.Redis, assessment_id, path: str, wall_clock_minutes: int) -> None:
    k = prefix(assessment_id) + "blocked"
    r.sadd(k, path)
    r.expire(k, _ttl(wall_clock_minutes))


def blocked_paths(r: redis.Redis, assessment_id) -> set[str]:
    return set(r.smembers(prefix(assessment_id) + "blocked"))


def note_round(r: redis.Redis, assessment_id, round_no: int, note: dict, wall_clock_minutes: int) -> None:
    k = prefix(assessment_id) + "notes"
    r.hset(k, str(round_no), json.dumps(note, default=str))
    r.expire(k, _ttl(wall_clock_minutes))


def notes(r: redis.Redis, assessment_id) -> dict[int, dict]:
    return {int(k): json.loads(v) for k, v in r.hgetall(prefix(assessment_id) + "notes").items()}


def keys(r: redis.Redis, assessment_id) -> list[str]:
    return list(r.scan_iter(prefix(assessment_id) + "*"))


def bloom(r: redis.Redis, assessment_id, wall_clock_minutes: int):
    """DA-15: per-run discovery de-duplication filter (erased with the rest of short-term memory)."""
    from asvas.dedupe import BloomFilter
    return BloomFilter(r, prefix(assessment_id) + "bloom", _ttl(wall_clock_minutes))
