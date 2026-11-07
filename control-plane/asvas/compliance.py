"""Read-only control status for auditors (requirement UI-04; spec pp. 60, 77-78).

Every item is computed from the live system (database, configuration, policy files) at request time. Statuses:
"pass" = the control is in effect and its check succeeded; "attention" = the control is missing, degraded or its
check failed; "info" = a fact an auditor needs, with no judgement attached. Nothing here is a compliance
certification; mapping to NIST / ISO / SOC 2 (DA-12) is not implemented.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from sqlalchemy import Connection

from asvas.audit import verify_chain
from asvas.config import get_settings
from asvas.db import row, rows


def _item(cid: str, req: str, title: str, status: str, detail: str, data: dict | None = None) -> dict[str, Any]:
    return {"id": cid, "requirement": req, "title": title, "status": status, "detail": detail, "data": data or {}}


def policy_base() -> Path:
    return Path(os.environ.get("ASVAS_POLICY_DIR") or Path(__file__).resolve().parents[2] / "policies")


def policy_files() -> list[tuple[Path, str]]:
    base = policy_base()
    return [(f, hashlib.sha256(f.read_bytes()).hexdigest()) for f in sorted(base.rglob("*.rego"))
            if not f.name.endswith("_test.rego")]


def _policy_digest() -> dict[str, str]:
    return {str(f.relative_to(policy_base())): h for f, h in policy_files()}


def controls(conn: Connection, tenant_id, policy_health: dict) -> list[dict[str, Any]]:
    s = get_settings()
    items = []
    chain = verify_chain(conn, tenant_id)
    items.append(_item("audit-chain", "DA-10", "Audit ledger hash chain", "pass" if chain["ok"] else "attention",
                       f"{chain['events']} events verified" if chain["ok"] else f"chain broken at event {chain['broken_at']}",
                       chain))
    cp = row(conn, "SELECT seq, to_id, created_at, key_fingerprint FROM audit_checkpoints ORDER BY seq DESC LIMIT 1")
    since = row(conn, "SELECT count(*) AS n FROM audit_events WHERE id > :i", i=cp["to_id"] if cp else 0)["n"]
    items.append(_item("audit-export", "DA-10", "Signed write-once audit export",
                       "pass" if cp else "attention",
                       (f"checkpoint #{cp['seq']} covers events up to {cp['to_id']}; {since} events not yet exported"
                        if cp else "no export checkpoint yet (run `asvas audit-export`)"),
                       {"last_checkpoint": cp, "events_since": since}))
    ap = {r["status"]: r["n"] for r in rows(conn, "SELECT status, count(*) AS n FROM approvals GROUP BY status")}
    decided = row(conn, "SELECT count(*) AS n, count(signature) AS signed FROM approvals WHERE decided_at IS NOT NULL")
    keys = row(conn, "SELECT count(*) FILTER (WHERE revoked_at IS NULL) AS active, "
                     "count(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked FROM approver_keys")
    unsigned = decided["n"] - decided["signed"]
    items.append(_item("approval-signatures", "PO-04", "Approver-signed decisions",
                       "pass" if s.approval_signatures == "required" and unsigned == 0 else "attention",
                       f"{decided['signed']}/{decided['n']} decisions signed; signatures {s.approval_signatures}; "
                       f"{keys['active']} active / {keys['revoked']} revoked approver keys",
                       {"approvals_by_status": ap, "decided": decided, "keys": keys}))
    self_refused = row(conn, "SELECT count(*) AS n FROM audit_events WHERE event_type = "
                             "'approval.self_approval_refused'")["n"]
    items.append(_item("dual-control", "CP-09", "Dual control on approvals", "info",
                       f"requester can never approve; {self_refused} self-approval attempts refused"))
    ev = row(conn, "SELECT count(*) AS n, count(enc_alg) AS enc FROM evidence")
    keks = [r["kek_id"] for r in rows(conn, "SELECT DISTINCT kek_id FROM evidence WHERE kek_id IS NOT NULL")]
    items.append(_item("encryption-at-rest", "CP-11", "Evidence encrypted at rest",
                       "pass" if ev["n"] == ev["enc"] else "attention",
                       f"{ev['enc']}/{ev['n']} evidence records sealed (AES-256-GCM envelope); key ids in use: "
                       f"{', '.join(keks) or 'none'}", {"evidence": ev, "kek_ids": keks}))
    tls = {"database": "sslmode=verify-full" in s.database_url, "redis": s.redis_url.startswith("rediss://"),
           "policy_engine": s.opa_url.startswith("https://"), "api": bool(s.api_tls_cert and s.api_tls_key),
           "executor_grpc_mtls": bool(s.executor_tls_ca and s.executor_tls_cert)}
    items.append(_item("transport-tls", "CP-10", "Transport encryption (as configured on this control plane)",
                       "pass" if all(tls.values()) else "attention",
                       ", ".join(f"{k}: {'TLS' if v else 'PLAINTEXT'}" for k, v in tls.items()), tls))
    ctl = row(conn, "SELECT emergency_stop, stopped_at FROM tenant_controls WHERE tenant_id = :t", t=str(tenant_id))
    items.append(_item("emergency-stop", "PO-15", "Emergency stop", "info",
                       "ENGAGED" if ctl and ctl["emergency_stop"] else "not engaged", ctl or {}))
    digest = _policy_digest()
    items.append(_item("policy-engine", "PO-01", "Policy engine (OPA) loaded, fail-closed",
                       "pass" if policy_health.get("policy_loaded") else "attention",
                       ("policy loaded" if policy_health.get("policy_loaded") else "policy NOT loaded — all actions denied")
                       + f"; {len(digest)} policy file(s) on disk", {"files_sha256": digest}))
    parts = row(conn, "SELECT count(*) AS n, min(c.relname) AS oldest FROM pg_inherits i JOIN pg_class c ON "
                      "c.oid = i.inhrelid WHERE i.inhparent = 'execution_log'::regclass")
    items.append(_item("retention", "DA-14", "Transient log retention", "info",
                       f"execution logs, planner checkpoints and stream entries wiped after "
                       f"{s.transient_retention_days} days; {parts['n']} daily partitions (oldest {parts['oldest']})",
                       {"retention_days": s.transient_retention_days, "partitions": parts}))
    items.append(_item("isolation", "PO-10", "Execution isolation", "attention",
                       "Firecracker microVMs are not available on this host; executors use the development process "
                       "sandbox (separate UID, no_new_privs, rlimits, nftables egress) — not equivalent isolation"))
    return items
