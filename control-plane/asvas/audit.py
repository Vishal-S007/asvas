"""Append-only, per-tenant hash-chained audit ledger (spec pp. 14, 42, 58, 63)."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from sqlalchemy import Connection, text

from asvas.canonical import canonical_json, sha256_hex

GENESIS = "0" * 64


def _jsonable(data: Any) -> Any:
    return json.loads(json.dumps(data, default=str))


def record(conn: Connection, tenant_id: uuid.UUID | str, actor: str, event_type: str,
           data: dict[str, Any] | None = None, assessment_id: uuid.UUID | str | None = None) -> str:
    """Append one event inside the caller's transaction (so state change and audit commit atomically)."""
    payload = _jsonable(data or {})
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext('asvas_audit:' || :t))"), {"t": str(tenant_id)})
    prev = conn.execute(text("SELECT hash FROM audit_events WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"),
                        {"t": str(tenant_id)}).scalar() or GENESIS
    created = dt.datetime.now(dt.UTC)
    body = {
        "tenant_id": str(tenant_id), "assessment_id": str(assessment_id) if assessment_id else None,
        "actor": actor, "event_type": event_type, "data": _floats_to_str(payload),
        "created_at": created.isoformat(), "prev_hash": prev,
    }
    h = sha256_hex(canonical_json(body))
    conn.execute(text(
        "INSERT INTO audit_events (tenant_id, assessment_id, actor, event_type, data, prev_hash, hash, created_at) "
        "VALUES (:t, :a, :actor, :et, CAST(:data AS jsonb), :prev, :hash, :created)"),
        {"t": str(tenant_id), "a": str(assessment_id) if assessment_id else None, "actor": actor,
         "et": event_type, "data": json.dumps(payload), "prev": prev, "hash": h, "created": created})
    return h


def _floats_to_str(obj: Any) -> Any:
    if isinstance(obj, float):
        return repr(obj)
    if isinstance(obj, dict):
        return {k: _floats_to_str(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_floats_to_str(v) for v in obj]
    return obj


def verify_chain(conn: Connection, tenant_id: uuid.UUID | str) -> dict[str, Any]:
    """Recompute the chain. Returns {"ok": bool, "events": n, "broken_at": id|None}."""
    prev = GENESIS
    n = 0
    for r in conn.execute(text("SELECT * FROM audit_events WHERE tenant_id = :t ORDER BY id"), {"t": str(tenant_id)}):
        m = r._mapping
        if m["prev_hash"] != prev or event_hash(event_record(m)) != m["hash"]:
            return {"ok": False, "events": n, "broken_at": m["id"]}
        prev = m["hash"]
        n += 1
    return {"ok": True, "events": n, "broken_at": None}


def event_record(m) -> dict[str, Any]:
    """Portable form of one stored event (used by verification and the WORM export)."""
    return {"id": m["id"], "tenant_id": str(m["tenant_id"]),
            "assessment_id": str(m["assessment_id"]) if m["assessment_id"] else None,
            "actor": m["actor"], "event_type": m["event_type"], "data": m["data"],
            "created_at": m["created_at"].astimezone(dt.UTC).isoformat(), "prev_hash": m["prev_hash"], "hash": m["hash"]}


def event_hash(ev: dict[str, Any]) -> str:
    body = {k: ev[k] for k in ("tenant_id", "assessment_id", "actor", "event_type", "created_at", "prev_hash")}
    body["data"] = _floats_to_str(ev["data"])
    return sha256_hex(canonical_json(body))
