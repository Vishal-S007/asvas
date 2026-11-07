"""Key-ring operations: status, rotation and data-key re-wrapping (CP-11)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text

from asvas import audit, crypto
from asvas.db import list_tenant_ids, rows, tenant_tx


def status() -> dict[str, Any]:
    kr = crypto.keyring()
    out: dict[str, Any] = {"active_kek": kr.active, "keks": sorted(kr.keys), "by_kek": {}, "plaintext_legacy": 0}
    for t in list_tenant_ids():
        with tenant_tx(t) as conn:
            for table in ("evidence", "reports"):
                for r in rows(conn, f"SELECT kek_id, count(*) n FROM {table} WHERE content IS NOT NULL GROUP BY kek_id"):
                    if r["kek_id"] is None:
                        out["plaintext_legacy"] += r["n"]
                    else:
                        out["by_kek"][r["kek_id"]] = out["by_kek"].get(r["kek_id"], 0) + r["n"]
    return out


def rotate() -> dict[str, Any]:
    kr = crypto.keyring()
    old = kr.active
    new = kr.rotate()
    return {"previous_active": old, "active": new, "note": "run `asvas keys rewrap` to move stored data keys"}


def rewrap(batch: int = 500) -> dict[str, Any]:
    """Re-wrap every stored data key under the active KEK. Sealed content is never rewritten."""
    kr = crypto.keyring()
    total = 0
    for t in list_tenant_ids():
        while moved := _rewrap_batch(kr, t, batch):
            total += moved
    return {"rewrapped": total, "active_kek": kr.active}


def _rewrap_batch(kr: crypto.KeyRing, tenant_id, batch: int) -> int:
    moved = 0
    with tenant_tx(tenant_id) as conn:
        for r in rows(conn, "SELECT id, tenant_id, job_id, attempt, seq, kek_id, dek_wrapped FROM evidence "
                            "WHERE enc_alg IS NOT NULL AND kek_id <> :a LIMIT :n", a=kr.active, n=batch):
            w, kid = kr.rewrap(bytes(r["dek_wrapped"]), r["kek_id"],
                               crypto.evidence_aad(r["tenant_id"], r["job_id"], r["attempt"], r["seq"]))
            conn.execute(text("UPDATE evidence SET dek_wrapped=:w, kek_id=:k WHERE id=:id"),
                         {"w": w, "k": kid, "id": str(r["id"])})
            moved += 1
        for r in rows(conn, "SELECT id, tenant_id, kek_id, dek_wrapped FROM reports "
                            "WHERE enc_alg IS NOT NULL AND kek_id <> :a LIMIT :n", a=kr.active, n=batch):
            w, kid = kr.rewrap(bytes(r["dek_wrapped"]), r["kek_id"], crypto.report_aad(r["tenant_id"], r["id"]))
            conn.execute(text("UPDATE reports SET dek_wrapped=:w, kek_id=:k WHERE id=:id"),
                         {"w": w, "k": kid, "id": str(r["id"])})
            moved += 1
        if moved:
            audit.record(conn, tenant_id, "system:keymgmt", "keys.rewrapped", {"active_kek": kr.active, "count": moved})
    return moved
