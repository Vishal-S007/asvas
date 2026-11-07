"""Transient execution log and retention (requirement DA-14; spec pp. 77, 84-85).

* `log()` appends an operational line to the day-partitioned `execution_log` (never evidence, never audit).
* `run()` is the daily maintenance task: create upcoming partitions, drop partitions past retention (30-day
  floor enforced in the database), delete LangGraph checkpoints of assessments that ended more than the
  retention period ago, and trim Redis Streams entries older than the retention period. Each tenant's
  deletions are recorded in its audit ledger. Evidence, findings and the audit ledger are not touched.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import redis
from sqlalchemy import Connection, text

from asvas import audit
from asvas.config import get_settings
from asvas.db import list_tenant_ids, rows, system_tx, tenant_tx
from asvas.orchestration import bus

log = logging.getLogger("asvas.retention")
LOCK_KEY = "asvas:maintenance:daily"


def write(conn: Connection, tenant_id, assessment_id, job_id, attempt: int, event: str, detail: dict) -> None:
    """Best effort: a missing partition or log failure must never roll back the caller's state change."""
    try:
        with conn.begin_nested():
            conn.execute(text(
                "INSERT INTO execution_log (tenant_id, assessment_id, job_id, attempt, event, detail) "
                "VALUES (:t, :a, :j, :n, :e, CAST(:d AS jsonb))"),
                {"t": str(tenant_id), "a": str(assessment_id) if assessment_id else None, "j": str(job_id),
                 "n": attempt, "e": event, "d": json.dumps(detail, default=str)})
    except Exception:  # noqa: BLE001
        log.warning("execution log write failed for job %s (%s)", job_id, event, exc_info=True)


def exchange_lines(exchanges: list[dict]) -> list[dict[str, Any]]:
    out = []
    for x in exchanges:
        req, resp = x.get("request") or {}, x.get("response") or {}
        out.append({"seq": x.get("seq"), "method": req.get("method"), "url": req.get("url"),
                    "resolved_ip": req.get("resolved_ip"), "status": resp.get("status"),
                    "duration_ms": x.get("duration_ms"), "error": x.get("error"),
                    "redirect": (x.get("redirect") or {}).get("decision")})
    return out


def run(r: redis.Redis | None = None, retention_days: int | None = None) -> dict[str, Any]:
    days = retention_days or get_settings().transient_retention_days
    with system_tx() as conn:
        created = [x[0] for x in conn.execute(text("SELECT asvas_ensure_log_partitions(7)"))]
        dropped = [dict(m._mapping) for m in conn.execute(
            text("SELECT * FROM asvas_drop_expired_log_partitions(:d)"), {"d": days})]
    per_tenant: dict[str, dict[str, Any]] = {}
    for d in dropped:
        if d["tenant_id"] is not None:
            per_tenant.setdefault(str(d["tenant_id"]), {"partitions": [], "rows": 0})
            per_tenant[str(d["tenant_id"])]["partitions"].append(d["partition_name"])
            per_tenant[str(d["tenant_id"])]["rows"] += d["row_count"]
    checkpoints = 0
    for t in list_tenant_ids():
        with tenant_tx(t) as conn:
            ids = [str(x["id"]) for x in rows(conn, "SELECT id FROM assessments WHERE status IN "
                                                    "('COMPLETED','FAILED','CANCELLED') AND finished_at < "
                                                    "now() - make_interval(days => :d)", d=days)]
            n = 0
            for aid in ids:
                for tbl in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                    n += conn.execute(text(f"DELETE FROM {tbl} WHERE thread_id LIKE :p"), {"p": aid + ":%"}).rowcount
            checkpoints += n
            info = per_tenant.get(str(t))
            if info or n:
                audit.record(conn, t, "system:retention", "retention.purged",
                             {"retention_days": days, "execution_log_partitions": (info or {}).get("partitions", []),
                              "execution_log_rows": (info or {}).get("rows", 0), "checkpoint_rows": n})
    trimmed = {}
    if r is not None:
        minid = f"{int((time.time() - days * 86400) * 1000)}-0"
        for s in (bus.JOBS, bus.RESULTS, bus.CONTROL, bus.ORCH):
            trimmed[s] = r.xtrim(s, minid=minid, approximate=False)
    res = {"retention_days": days, "partitions_created": created,
           "partitions_dropped": sorted({d["partition_name"] for d in dropped}), "checkpoint_rows_deleted": checkpoints,
           "stream_entries_trimmed": trimmed}
    log.info("retention run: %s", res)
    return res


def maybe_run_daily(r: redis.Redis) -> dict[str, Any] | None:
    """Run at most once per ~day across all orchestrators (Redis SET NX lock)."""
    if not r.set(LOCK_KEY, str(int(time.time())), nx=True, ex=23 * 3600):
        return None
    try:
        return run(r)
    except Exception:  # noqa: BLE001
        r.delete(LOCK_KEY)
        log.exception("retention run failed")
        return None
