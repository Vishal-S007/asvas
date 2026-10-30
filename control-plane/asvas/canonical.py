"""Canonical JSON + HMAC helpers shared (byte-for-byte) with the Go execution plane.

Canonical form: UTF-8, keys sorted, no whitespace, ASCII-only escaping (ensure_ascii). Only str/int/bool/
None/list/dict are allowed in signed material; floats are rejected to avoid cross-language drift.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def _check(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in canonical signed material")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("keys must be strings")
            _check(v)
    elif isinstance(obj, list):
        for v in obj:
            _check(v)


def canonical_json(obj: Any) -> str:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_hex(key, message), signature)


def binding_hash(assessment_id: str, job_id: str, tool_id: str, target: dict, params: dict) -> str:
    """Hash that an approval is bound to. Any change to tool, target or params changes it."""
    return sha256_hex(canonical_json({
        "assessment_id": str(assessment_id), "job_id": str(job_id), "tool_id": tool_id,
        "target": target, "params": params,
    }))
