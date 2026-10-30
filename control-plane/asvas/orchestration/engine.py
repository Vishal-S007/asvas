"""Assessment orchestration: start, plan, dispatch, approvals, result ingestion, retest, cancel, emergency stop.

All state changes go through statemachine.* and are audited in the same transaction.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import redis
from sqlalchemy import Connection, Engine, text

from asvas import audit
from asvas.canonical import binding_hash, canonical_json
from asvas.config import get_settings
from asvas.db import list_tenant_ids, row, rows, tenant_tx
from asvas.evidence import (
    correlate_assets,
    evaluate_rules,
    finding_fingerprint,
    record_findings,
    store_exchanges,
)
from asvas.orchestration import bus
from asvas.planning.graph import PlanState, build_planner, record_planning_audit
from asvas.planning.providers import ModelProvider, get_provider
from asvas.planning.validate import fingerprint
from asvas.policy import OpaClient, build_input
from asvas.scope import Scope, TestingPolicy, check_authorization_window, resolve
from asvas.statemachine import ASSESSMENT_TERMINAL, IllegalTransition, transition_assessment, transition_job
from asvas.tools import REGISTRY

log = logging.getLogger("asvas.orchestrator")


class OrchestrationError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


@dataclass
class Deps:
    engine: Engine | None = None
    redis: redis.Redis | None = None
    opa: OpaClient | None = None
    provider_factory: Callable[[], ModelProvider] = get_provider
    resolve_fn: Callable[[str], list[str]] = resolve
    checkpointer: Any = None

    @property
    def r(self) -> redis.Redis:
        return self.redis or bus.get_redis()

    @property
    def policy(self) -> OpaClient:
        if self.opa is None:
            self.opa = OpaClient()
        return self.opa


class AuditedRefusal(OrchestrationError):
    """A refusal whose audit/state changes must be committed before the error propagates."""


@contextmanager
def _tx(deps: Deps, tenant_id):
    refusal: AuditedRefusal | None = None
    with tenant_tx(tenant_id, deps.engine) as conn:
        try:
            yield conn
        except AuditedRefusal as e:
            refusal = e  # swallow inside the transaction so it COMMITs, then re-raise below
    if refusal is not None:
        raise refusal


def _halted(conn: Connection, tenant_id, assessment: dict) -> bool:
    stop = conn.execute(text("SELECT emergency_stop FROM tenant_controls WHERE tenant_id = :t"),
                        {"t": str(tenant_id)}).scalar()
    return bool(stop) or assessment["status"] in ("CANCELLING", "CANCELLED")


# --------------------------------------------------------------------------------------------- start

def start_assessment(deps: Deps, tenant_id, assessment_id, actor_id) -> dict:
    with _tx(deps, tenant_id) as conn:
        a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=str(assessment_id))
        if a is None:
            raise OrchestrationError("assessment not found", 404)
        if a["status"] != "DRAFT":
            raise OrchestrationError(f"assessment is {a['status']}; only DRAFT assessments can be started")
        if _halted(conn, tenant_id, a):
            raise OrchestrationError("tenant is under emergency stop")
        scope = Scope.model_validate(a["scope"])
        TestingPolicy.model_validate(a["testing_policy"])
        problems = check_authorization_window(scope)
        if problems:
            audit.record(conn, tenant_id, f"user:{actor_id}", "assessment.start_refused", {"reasons": problems}, assessment_id)
            raise AuditedRefusal("; ".join(problems), 422)
        frozen = canonical_json({"scope": scope.model_dump(mode="json"), "policy": a["testing_policy"]})
        conn.execute(text("UPDATE assessments SET frozen_scope_doc = :d, started_by = :u, started_at = now() WHERE id = :id"),
                     {"d": frozen, "u": str(actor_id), "id": str(assessment_id)})
        transition_assessment(conn, tenant_id, assessment_id, "PLANNING", f"user:{actor_id}",
                              extra={"frozen_scope_sha256": __import__("hashlib").sha256(frozen.encode()).hexdigest()})
    bus.publish_orchestrator(deps.r, {"type": "plan", "tenant_id": str(tenant_id), "assessment_id": str(assessment_id)})
    return {"assessment_id": str(assessment_id), "status": "PLANNING"}


# --------------------------------------------------------------------------------------------- planning

def _materialize(deps: Deps):
    def fn(conn: Connection, a: dict, state: PlanState) -> None:
        tenant_id, aid = a["tenant_id"], a["id"]
        round_no = state["round"]
        objective_key = f"round-{round_no}"
        _plan_node(conn, tenant_id, aid, "objective", None, -1, "objective",
                   "Validate configuration of in-scope targets", "accepted", [], {})
        _plan_node(conn, tenant_id, aid, objective_key, "objective", round_no, "round",
                   f"Planning round {round_no} ({state.get('provider_name')})", "accepted", [],
                   {"is_live_ai": state.get("is_live_ai"), "summary": (state.get("proposal") or {}).get("summary")})
        for rj in state.get("rejected", []):
            s = rj["step"]
            _plan_node(conn, tenant_id, aid, f"r{round_no}-rej-{uuid.uuid4().hex[:8]}", objective_key, round_no, "step",
                       f"{s['tool_id']} → {s['target']['scheme']}://{s['target']['host']}:{s['target']['port']}",
                       "rejected", rj["reasons"], {"proposal": s})
        for acc in state.get("accepted", []):
            s = acc["step"]
            node_key = f"r{round_no}-{s['step_id']}"
            job_id = create_job(deps, conn, a, tool_id=s["tool_id"], target=acc["target"], params=acc["params"],
                                resolved_ips=acc["resolved_ips"], fp=acc["fingerprint"], plan_node_key=node_key,
                                actor="system:planner")
            j = row(conn, "SELECT status, policy_decision FROM jobs WHERE id = :id", id=str(job_id))
            parent = objective_key if not s["depends_on"] else f"r{round_no}-{s['depends_on'][0]}"
            _plan_node(conn, tenant_id, aid, node_key, parent, round_no, "step",
                       f"{s['tool_id']} → {acc['target']['scheme']}://{acc['target']['host']}:{acc['target']['port']}",
                       "denied" if j["status"] == "DENIED" else "job",
                       (j["policy_decision"] or {}).get("deny_reasons", []),
                       {"job_id": str(job_id), "rationale": s["rationale"]})
        conn.execute(text(
            "UPDATE assessments SET planning_rounds = planning_rounds + 1, tokens_used = tokens_used + :tok, "
            "provider_name = :p, provider_is_live_ai = :live, planner_done = :done WHERE id = :id"),
            {"tok": state.get("tokens", 0), "p": state.get("provider_name"), "live": state.get("is_live_ai"),
             "done": bool(state.get("done")), "id": str(aid)})
        record_planning_audit(conn, tenant_id, aid, state)
    return fn


def _plan_node(conn, tenant_id, aid, key, parent, round_no, kind, label, status, reasons, data) -> None:
    conn.execute(text(
        "INSERT INTO plan_nodes (tenant_id, assessment_id, node_key, parent_key, round, kind, label, status, reasons, data) "
        "VALUES (:t,:a,:k,:p,:r,:kind,:l,:s,CAST(:re AS jsonb),CAST(:d AS jsonb)) ON CONFLICT (assessment_id, node_key) DO NOTHING"),
        {"t": str(tenant_id), "a": str(aid), "k": key, "p": parent, "r": round_no, "kind": kind, "l": label,
         "s": status, "re": json.dumps(reasons), "d": json.dumps(data)})


def run_planning_round(deps: Deps, tenant_id, assessment_id) -> None:
    with _tx(deps, tenant_id) as conn:
        a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=str(assessment_id))
        if a is None or a["status"] != "PLANNING":
            return
        round_no = a["planning_rounds"]
    try:
        provider = deps.provider_factory()
    except Exception as e:  # noqa: BLE001 - e.g. missing API key: fail honestly
        _fail(deps, tenant_id, assessment_id, f"planning provider unavailable: {e}")
        return
    graph = build_planner(deps.engine, provider, _materialize(deps), deps.resolve_fn, deps.checkpointer)
    cfg = {"configurable": {"thread_id": f"{assessment_id}:{round_no}"}, "recursion_limit": 12}
    try:
        final = graph.invoke({"tenant_id": str(tenant_id), "assessment_id": str(assessment_id), "round": round_no,
                              "attempts": 0, "tokens": 0, "rejected": []}, cfg)
    except Exception as e:
        log.exception("planning graph crashed")
        _fail(deps, tenant_id, assessment_id, f"planning graph error: {type(e).__name__}: {e}")
        return
    if final.get("error"):
        with _tx(deps, tenant_id) as conn:
            conn.execute(text("UPDATE assessments SET provider_name = :p, provider_is_live_ai = :l WHERE id = :id"),
                         {"p": final.get("provider_name"), "l": final.get("is_live_ai"), "id": str(assessment_id)})
        _fail(deps, tenant_id, assessment_id, final["error"])
        return
    advance(deps, tenant_id, assessment_id, from_planning=True)


def _fail(deps: Deps, tenant_id, assessment_id, reason: str) -> None:
    with _tx(deps, tenant_id) as conn:
        a = row(conn, "SELECT status FROM assessments WHERE id = :id FOR UPDATE", id=str(assessment_id))
        if a is None or a["status"] in ASSESSMENT_TERMINAL or a["status"] == "CANCELLING":
            return
        for j in rows(conn, "SELECT id, status FROM jobs WHERE assessment_id = :a AND status IN "
                            "('PROPOSED','AWAITING_APPROVAL','QUEUED')", a=str(assessment_id)):
            transition_job(conn, tenant_id, j["id"], "CANCELLED", "system:orchestrator", "assessment failed")
        conn.execute(text("UPDATE approvals SET status='INVALIDATED', reason='assessment failed' "
                          "WHERE assessment_id = :a AND status IN ('PENDING','APPROVED')"), {"a": str(assessment_id)})
        transition_assessment(conn, tenant_id, assessment_id, "FAILED", "system:orchestrator", reason)
    deps.r.set(bus.halt_key_assessment(str(assessment_id)), "failed", ex=86400)
    bus.publish_control(deps.r, {"type": "cancel_assessment", "tenant_id": str(tenant_id),
                                 "assessment_id": str(assessment_id), "reason": "failed"})


# --------------------------------------------------------------------------------------------- jobs

def _policy_for(deps: Deps, conn, a: dict, job: dict, resolved_ips: list[str], approval: dict | None):
    spec = REGISTRY[job["tool_id"]]
    pol = a["testing_policy"]
    return deps.policy.evaluate(build_input(
        tool_id=job["tool_id"], risk_tier=spec.risk_tier, category=spec.category, max_requests=spec.max_requests,
        rps=pol["max_requests_per_second"], timeout_seconds=pol["job_timeout_seconds"], target=job["target"],
        resolved_ips=resolved_ips, scope=Scope.model_validate(a["scope"]).model_dump(mode="json"), policy=pol,
        approval=approval, halted=_halted(conn, a["tenant_id"], a)))


def create_job(deps: Deps, conn: Connection, a: dict, *, tool_id: str, target: dict, params: dict,
               resolved_ips: list[str], fp: str, plan_node_key: str | None, actor: str,
               retest_of: uuid.UUID | None = None, requested_by=None) -> uuid.UUID:
    spec = REGISTRY[tool_id]
    pol = a["testing_policy"]
    job_id = conn.execute(text(
        "INSERT INTO jobs (tenant_id, assessment_id, plan_node_key, tool_id, risk_tier, category, target, params, "
        "fingerprint, status, max_attempts, timeout_seconds, retest_of_finding) VALUES (:t,:a,:pk,:tool,:risk,:cat,"
        "CAST(:target AS jsonb),CAST(:params AS jsonb),:fp,'PROPOSED',:ma,:to,:rt) RETURNING id"),
        {"t": str(a["tenant_id"]), "a": str(a["id"]), "pk": plan_node_key, "tool": tool_id, "risk": spec.risk_tier,
         "cat": spec.category, "target": json.dumps(target), "params": json.dumps(params), "fp": fp,
         "ma": pol["max_attempts"], "to": pol["job_timeout_seconds"],
         "rt": str(retest_of) if retest_of else None}).scalar()
    audit.record(conn, a["tenant_id"], actor, "job.proposed",
                 {"job_id": str(job_id), "tool_id": tool_id, "target": target, "params": params,
                  "resolved_ips": resolved_ips}, a["id"])
    job = {"id": job_id, "tool_id": tool_id, "target": target, "params": params}
    decision = _policy_for(deps, conn, a, job, resolved_ips, None)
    conn.execute(text("UPDATE jobs SET policy_decision = CAST(:d AS jsonb) WHERE id = :id"),
                 {"d": json.dumps(decision.as_dict()), "id": str(job_id)})
    audit.record(conn, a["tenant_id"], "system:policy", "policy.decision",
                 {"job_id": str(job_id), "stage": "create", **decision.as_dict()}, a["id"])
    if decision.deny_reasons:
        transition_job(conn, a["tenant_id"], job_id, "DENIED", "system:policy", "; ".join(decision.deny_reasons))
    elif decision.require_approval:
        conn.execute(text("UPDATE jobs SET requires_approval = true WHERE id = :id"), {"id": str(job_id)})
        transition_job(conn, a["tenant_id"], job_id, "AWAITING_APPROVAL", "system:policy")
        _request_approval(conn, a, job_id, requested_by or a["started_by"])
    elif decision.allow:
        transition_job(conn, a["tenant_id"], job_id, "QUEUED", "system:policy")
    else:
        transition_job(conn, a["tenant_id"], job_id, "DENIED", "system:policy", "policy did not allow")
    return job_id


def _request_approval(conn: Connection, a: dict, job_id, requested_by) -> uuid.UUID:
    j = row(conn, "SELECT * FROM jobs WHERE id = :id", id=str(job_id))
    bh = binding_hash(str(a["id"]), str(job_id), j["tool_id"], j["target"], j["params"])
    ttl = get_settings().approval_ttl_minutes
    aid = conn.execute(text(
        "INSERT INTO approvals (tenant_id, assessment_id, job_id, binding_hash, binding_summary, status, requested_by, expires_at) "
        "VALUES (:t,:a,:j,:bh,CAST(:sum AS jsonb),'PENDING',:rb, now() + make_interval(mins => :ttl)) RETURNING id"),
        {"t": str(a["tenant_id"]), "a": str(a["id"]), "j": str(job_id), "bh": bh,
         "sum": json.dumps({"tool_id": j["tool_id"], "risk_tier": j["risk_tier"], "target": j["target"], "params": j["params"]}),
         "rb": str(requested_by) if requested_by else None, "ttl": ttl}).scalar()
    conn.execute(text("UPDATE jobs SET approval_id = :ap WHERE id = :id"), {"ap": str(aid), "id": str(job_id)})
    audit.record(conn, a["tenant_id"], "system:policy", "approval.requested",
                 {"approval_id": str(aid), "job_id": str(job_id), "binding_hash": bh, "ttl_minutes": ttl}, a["id"])
    return aid


def decide_approval(deps: Deps, tenant_id, approval_id, actor_id, actor_role: str, decision: str,
                    presented_binding_hash: str, reason: str | None = None) -> dict:
    with _tx(deps, tenant_id) as conn:
        ap = row(conn, "SELECT * FROM approvals WHERE id = :id FOR UPDATE", id=str(approval_id))
        if ap is None:
            raise OrchestrationError("approval not found", 404)
        actor = f"user:{actor_id}"
        if ap["status"] != "PENDING":
            raise OrchestrationError(f"approval is {ap['status']}")
        if ap["expires_at"] <= dt.datetime.now(dt.UTC):
            conn.execute(text("UPDATE approvals SET status='EXPIRED' WHERE id=:id"), {"id": str(approval_id)})
            audit.record(conn, tenant_id, actor, "approval.expired", {"approval_id": str(approval_id)}, ap["assessment_id"])
            raise AuditedRefusal("approval request has expired", 410)
        if ap["requested_by"] and str(ap["requested_by"]) == str(actor_id):
            audit.record(conn, tenant_id, actor, "approval.self_approval_refused", {"approval_id": str(approval_id)},
                         ap["assessment_id"])
            raise AuditedRefusal("the requester cannot approve their own action (dual control)", 403)
        job = row(conn, "SELECT * FROM jobs WHERE id = :id FOR UPDATE", id=str(ap["job_id"]))
        current = binding_hash(str(ap["assessment_id"]), str(job["id"]), job["tool_id"], job["target"], job["params"])
        if presented_binding_hash != ap["binding_hash"] or current != ap["binding_hash"]:
            conn.execute(text("UPDATE approvals SET status='INVALIDATED', reason='binding mismatch' WHERE id=:id"),
                         {"id": str(approval_id)})
            audit.record(conn, tenant_id, actor, "approval.binding_mismatch",
                         {"approval_id": str(approval_id), "presented": presented_binding_hash,
                          "stored": ap["binding_hash"], "current": current}, ap["assessment_id"])
            if job["status"] == "AWAITING_APPROVAL":
                transition_job(conn, tenant_id, job["id"], "DENIED", "system:approvals", "approval binding mismatch")
            raise AuditedRefusal("action parameters changed since approval was requested; approval invalidated")
        if decision == "approve":
            exp = int(ap["expires_at"].timestamp())
            token = bus.approval_token(str(approval_id), ap["binding_hash"], exp)
            conn.execute(text("UPDATE approvals SET status='APPROVED', decided_by=:u, decided_at=now(), token=:tok, "
                              "reason=:r WHERE id=:id"),
                         {"u": str(actor_id), "tok": token, "r": reason, "id": str(approval_id)})
            audit.record(conn, tenant_id, actor, "approval.approved",
                         {"approval_id": str(approval_id), "job_id": str(job["id"]), "binding_hash": ap["binding_hash"],
                          "expires_at": ap["expires_at"].isoformat(), "role": actor_role}, ap["assessment_id"])
            transition_job(conn, tenant_id, job["id"], "QUEUED", actor)
        else:
            conn.execute(text("UPDATE approvals SET status='REJECTED', decided_by=:u, decided_at=now(), reason=:r WHERE id=:id"),
                         {"u": str(actor_id), "r": reason, "id": str(approval_id)})
            audit.record(conn, tenant_id, actor, "approval.rejected", {"approval_id": str(approval_id), "reason": reason},
                         ap["assessment_id"])
            transition_job(conn, tenant_id, job["id"], "DENIED", actor, "approval rejected")
        assessment_id = ap["assessment_id"]
    advance(deps, tenant_id, assessment_id)
    return {"approval_id": str(approval_id), "status": "APPROVED" if decision == "approve" else "REJECTED"}


def _dispatch(deps: Deps, conn: Connection, a: dict, job: dict) -> bool:
    """Re-verify everything at dispatch time, then publish a signed envelope. Returns True if dispatched."""
    tenant_id = a["tenant_id"]
    approval_payload = None
    approval_input = None
    if job["requires_approval"]:
        ap = row(conn, "SELECT * FROM approvals WHERE id = :id FOR UPDATE", id=str(job["approval_id"]))
        current = binding_hash(str(a["id"]), str(job["id"]), job["tool_id"], job["target"], job["params"])
        if ap is None or ap["status"] != "APPROVED":
            transition_job(conn, tenant_id, job["id"], "DENIED", "system:dispatcher", "no valid approval")
            return False
        if ap["binding_hash"] != current:
            conn.execute(text("UPDATE approvals SET status='INVALIDATED', reason='parameters changed' WHERE id=:id"),
                         {"id": str(ap["id"])})
            audit.record(conn, tenant_id, "system:dispatcher", "approval.binding_mismatch",
                         {"approval_id": str(ap["id"]), "stored": ap["binding_hash"], "current": current}, a["id"])
            transition_job(conn, tenant_id, job["id"], "DENIED", "system:dispatcher", "approval binding mismatch")
            return False
        if ap["expires_at"] <= dt.datetime.now(dt.UTC):
            conn.execute(text("UPDATE approvals SET status='EXPIRED' WHERE id=:id"), {"id": str(ap["id"])})
            audit.record(conn, tenant_id, "system:dispatcher", "approval.expired", {"approval_id": str(ap["id"])}, a["id"])
            transition_job(conn, tenant_id, job["id"], "AWAITING_APPROVAL", "system:dispatcher", "approval expired")
            _request_approval(conn, a, job["id"], a["started_by"])
            return False
        exp = int(ap["expires_at"].timestamp())
        approval_payload = {"approval_id": str(ap["id"]), "binding_hash": ap["binding_hash"], "expires_unix": exp,
                            "token": ap["token"]}
        approval_input = {"present": True, "verified": True, "expires_unix": exp}
    try:
        ips = deps.resolve_fn(job["target"]["host"])
    except OSError as e:
        ips = []
        log.warning("resolve failed: %s", e)
    decision = _policy_for(deps, conn, a, job, ips, approval_input)
    audit.record(conn, tenant_id, "system:policy", "policy.decision",
                 {"job_id": str(job["id"]), "stage": "dispatch", "resolved_ips": ips, **decision.as_dict()}, a["id"])
    if not decision.allow:
        transition_job(conn, tenant_id, job["id"], "DENIED", "system:policy",
                       "; ".join(decision.deny_reasons) or "policy did not allow")
        return False
    attempt = job["attempt"] + 1
    spec = REGISTRY[job["tool_id"]]
    pol = a["testing_policy"]
    deadline = int(time.time()) + job["timeout_seconds"]
    frozen = json.loads(a["frozen_scope_doc"])
    envelope = {
        "v": 1, "job_id": str(job["id"]), "attempt": attempt, "tenant_id": str(tenant_id), "assessment_id": str(a["id"]),
        "tool_id": job["tool_id"], "risk_tier": spec.risk_tier, "category": spec.category,
        "target": job["target"], "params": job["params"], "max_requests": spec.max_requests,
        "requests_per_second": pol["max_requests_per_second"], "timeout_seconds": job["timeout_seconds"],
        "deadline_unix": deadline, "issued_unix": int(time.time()), "scope": frozen["scope"], "policy": frozen["policy"],
        "approval": approval_payload,
    }
    conn.execute(text("UPDATE jobs SET attempt = :att, dispatched_at = now(), deadline_at = to_timestamp(:dl) "
                      "WHERE id = :id"), {"att": attempt, "dl": deadline, "id": str(job["id"])})
    transition_job(conn, tenant_id, job["id"], "RUNNING", "system:dispatcher", extra={"deadline_unix": deadline})
    if approval_payload:
        conn.execute(text("UPDATE approvals SET status='CONSUMED' WHERE id=:id"), {"id": approval_payload["approval_id"]})
    msg_id = bus.publish_job(deps.r, envelope)
    audit.record(conn, tenant_id, "system:dispatcher", "tool.dispatched",
                 {"job_id": str(job["id"]), "attempt": attempt, "stream_id": msg_id, "tool_id": job["tool_id"],
                  "target": job["target"], "params": job["params"]}, a["id"])
    return True


# --------------------------------------------------------------------------------------------- reconciliation

def advance(deps: Deps, tenant_id, assessment_id, from_planning: bool = False) -> str | None:
    """Idempotent reconciliation step: dispatch, move status, replan or finish. Serialised by row lock."""
    plan_again = False
    over_budget = False
    status: str | None = None
    with _tx(deps, tenant_id) as conn:
        a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=str(assessment_id))
        if a is None or a["status"] in ("FAILED", "CANCELLED", "DRAFT"):
            return a["status"] if a else None
        if a["status"] == "PLANNING" and not from_planning:
            return "PLANNING"
        counts = _counts(conn, assessment_id)
        if a["status"] == "CANCELLING":
            if not counts.get("RUNNING"):
                transition_assessment(conn, tenant_id, assessment_id, "CANCELLED", "system:orchestrator")
                _clear_short_term(deps, assessment_id)
                return "CANCELLED"
            return "CANCELLING"
        pol = a["testing_policy"]
        started = a["started_at"]
        if a["status"] != "COMPLETED" and started and \
                dt.datetime.now(dt.UTC) - started > dt.timedelta(minutes=pol["max_wall_clock_minutes"]):
            over_budget = True
        elif a["status"] == "COMPLETED" and not counts.get("QUEUED"):
            return "COMPLETED"
        else:
            if a["status"] == "COMPLETED":
                transition_assessment(conn, tenant_id, assessment_id, "RUNNING", "system:orchestrator", "retest")
                a["status"] = "RUNNING"
            running = counts.get("RUNNING", 0)
            for j in rows(conn, "SELECT * FROM jobs WHERE assessment_id = :a AND status = 'QUEUED' "
                                "ORDER BY created_at FOR UPDATE SKIP LOCKED", a=str(assessment_id)):
                if running >= pol["max_concurrency"]:
                    break
                if a["requests_used"] >= pol["max_total_requests"]:
                    transition_job(conn, tenant_id, j["id"], "CANCELLED", "system:orchestrator",
                                   "assessment request budget exhausted")
                    continue
                if _dispatch(deps, conn, a, j):
                    running += 1
            counts = _counts(conn, assessment_id)
            target = None
            if counts.get("RUNNING") or counts.get("QUEUED"):
                target = "RUNNING"
            elif counts.get("AWAITING_APPROVAL"):
                target = "AWAITING_APPROVAL"
            elif not a["planner_done"] and a["planning_rounds"] < pol["max_planning_rounds"]:
                target = "PLANNING"
                plan_again = True
            else:
                transition_assessment(conn, tenant_id, assessment_id, "REPORTING", "system:orchestrator")
                transition_assessment(conn, tenant_id, assessment_id, "COMPLETED", "system:orchestrator",
                                      extra=_summary(conn, assessment_id))
                _clear_short_term(deps, assessment_id)
                return "COMPLETED"
            if target != a["status"]:
                transition_assessment(conn, tenant_id, assessment_id, target, "system:orchestrator")
            status = target
    if over_budget:
        _fail(deps, tenant_id, assessment_id, "wall-clock budget exhausted")
        return "FAILED"
    if plan_again:
        bus.publish_orchestrator(deps.r, {"type": "plan", "tenant_id": str(tenant_id), "assessment_id": str(assessment_id)})
    return status


def _counts(conn, assessment_id) -> dict[str, int]:
    return {r["status"]: r["n"] for r in rows(conn, "SELECT status, count(*) n FROM jobs WHERE assessment_id = :a "
                                                    "GROUP BY status", a=str(assessment_id))}


def _summary(conn, assessment_id) -> dict:
    f = rows(conn, "SELECT severity, verification_status, count(*) n FROM findings WHERE assessment_id = :a "
                   "GROUP BY 1,2", a=str(assessment_id))
    return {"findings": [{"severity": r["severity"], "verification": r["verification_status"], "count": r["n"]} for r in f]}


def _clear_short_term(deps: Deps, assessment_id) -> None:
    """Short-term (Redis) state for a run is discarded when it ends (spec p.16). Halt key is kept 24h."""
    for k in deps.r.scan_iter(f"asvas:st:{assessment_id}:*"):
        deps.r.delete(k)


# --------------------------------------------------------------------------------------------- results

def ingest_result(deps: Deps, body: str, sig: str) -> str:
    res = bus.verify_result(body, sig)
    if res is None:
        log.error("result with invalid signature dropped")
        return "bad_signature"
    tenant_id, job_id, attempt = res["tenant_id"], res["job_id"], int(res["attempt"])
    with _tx(deps, tenant_id) as conn:
        job = row(conn, "SELECT * FROM jobs WHERE id = :id FOR UPDATE", id=job_id)
        if job is None:
            return "unknown_job"
        existing = conn.execute(text("SELECT 1 FROM job_results WHERE job_id = :j AND attempt = :a"),
                                {"j": job_id, "a": attempt}).first()
        if existing or job["attempt"] != attempt or job["status"] != "RUNNING":
            audit.record(conn, tenant_id, "system:ingest", "result.ignored_duplicate_or_stale",
                         {"job_id": job_id, "attempt": attempt, "job_status": job["status"],
                          "job_attempt": job["attempt"], "duplicate": bool(existing)}, job["assessment_id"])
            return "ignored"
        a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=str(job["assessment_id"]))
        status = res["status"]
        conn.execute(text("INSERT INTO job_results (tenant_id, job_id, attempt, status, worker_id, backend, egress_mode, "
                          "error, requests_used) VALUES (:t,:j,:a,:s,:w,:b,:e,:err,:n)"),
                     {"t": tenant_id, "j": job_id, "a": attempt, "s": status, "w": res.get("worker_id"),
                      "b": res.get("backend"), "e": res.get("egress_mode"), "err": res.get("error"),
                      "n": int(res.get("requests_used", 0))})
        conn.execute(text("UPDATE assessments SET requests_used = requests_used + :n WHERE id = :id"),
                     {"n": int(res.get("requests_used", 0)), "id": str(a["id"])})
        exchanges = res.get("exchanges") or []
        audit.record(conn, tenant_id, f"worker:{res.get('worker_id')}", "tool.result",
                     {"job_id": job_id, "attempt": attempt, "status": status, "error": res.get("error"),
                      "requests_used": res.get("requests_used"), "backend": res.get("backend"),
                      "egress_mode": res.get("egress_mode"), "exchanges": len(exchanges),
                      "executor_policy": res.get("policy_decision"),
                      "sandbox_attestation": res.get("sandbox_attestation"),
                      "blocked_redirects": [e["redirect"] for e in exchanges
                                            if (e.get("redirect") or {}).get("decision") == "blocked"]}, a["id"])
        ev_ids = store_exchanges(conn, tenant_id, a["id"], job_id, attempt, exchanges) if exchanges else {}
        if status == "SUCCEEDED":
            svc = correlate_assets(conn, tenant_id, a["id"], job["target"], exchanges)
            hits = evaluate_rules(job["tool_id"], job["target"], exchanges)
            if job["retest_of_finding"]:
                _complete_retest(conn, tenant_id, a, job, hits, ev_ids)
            else:
                record_findings(conn, tenant_id, a["id"], job, svc, ev_ids, hits)
            transition_job(conn, tenant_id, job_id, "SUCCEEDED", f"worker:{res.get('worker_id')}")
        elif status in ("FAILED", "TIMED_OUT"):
            transition_job(conn, tenant_id, job_id, status, f"worker:{res.get('worker_id')}", res.get("error"))
            _maybe_retry(conn, tenant_id, a, job)
        elif status == "CANCELLED":
            transition_job(conn, tenant_id, job_id, "CANCELLED", f"worker:{res.get('worker_id')}", res.get("error"))
        elif status == "DENIED":
            transition_job(conn, tenant_id, job_id, "DENIED", f"worker:{res.get('worker_id')}", res.get("error"))
        else:
            transition_job(conn, tenant_id, job_id, "FAILED", "system:ingest", f"unknown result status {status!r}")
        if job["retest_of_finding"] and status != "SUCCEEDED":
            conn.execute(text("UPDATE finding_retests SET outcome='inconclusive', completed_at=now() WHERE job_id=:j "
                              "AND outcome='pending'"), {"j": job_id})
        assessment_id = a["id"]
    advance(deps, tenant_id, assessment_id)
    return "ok"


def _maybe_retry(conn, tenant_id, a: dict, job: dict) -> None:
    if job["attempt"] < job["max_attempts"] and a["status"] not in ("CANCELLING", "CANCELLED", "FAILED"):
        transition_job(conn, tenant_id, job["id"], "QUEUED", "system:orchestrator",
                       extra={"retry": True, "next_attempt": job["attempt"] + 1})


def _complete_retest(conn, tenant_id, a: dict, job: dict, hits, ev_ids) -> None:
    rt = row(conn, "SELECT * FROM finding_retests WHERE job_id = :j", j=str(job["id"]))
    f = row(conn, "SELECT * FROM findings WHERE id = :id FOR UPDATE", id=str(job["retest_of_finding"]))
    service = f"{job['target']['scheme']}://{job['target']['host']}:{job['target']['port']}"
    present = any(finding_fingerprint(h.rule_id, service, h.key) == f["fingerprint"] for h in hits)
    outcome = "still_present" if present else "resolved"
    ev = [str(v) for v in ev_ids.values()]
    conn.execute(text("UPDATE finding_retests SET outcome=:o, evidence_ids=CAST(:ev AS uuid[]), completed_at=now() "
                      "WHERE id=:id"), {"o": outcome, "ev": "{" + ",".join(ev) + "}", "id": str(rt["id"])})
    conn.execute(text("UPDATE findings SET state=:s, updated_at=now() WHERE id=:id"),
                 {"s": "open" if present else "resolved", "id": str(f["id"])})
    audit.record(conn, tenant_id, "system:evidence", "finding.retested",
                 {"finding_id": str(f["id"]), "outcome": outcome, "evidence_ids": ev}, a["id"])


# --------------------------------------------------------------------------------------------- retest / cancel / stop

def request_retest(deps: Deps, tenant_id, finding_id, actor_id) -> dict:
    with _tx(deps, tenant_id) as conn:
        f = row(conn, "SELECT * FROM findings WHERE id = :id", id=str(finding_id))
        if f is None:
            raise OrchestrationError("finding not found", 404)
        a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=str(f["assessment_id"]))
        if a["status"] not in ("COMPLETED", "RUNNING", "AWAITING_APPROVAL"):
            raise OrchestrationError(f"cannot retest while assessment is {a['status']}")
        if _halted(conn, tenant_id, a):
            raise OrchestrationError("tenant is under emergency stop")
        problems = check_authorization_window(Scope.model_validate(a["scope"]))
        if problems:
            raise OrchestrationError("; ".join(problems), 422)
        if row(conn, "SELECT 1 x FROM finding_retests WHERE finding_id = :f AND outcome = 'pending'", f=str(finding_id)):
            raise OrchestrationError("a retest for this finding is already pending")
        orig = row(conn, "SELECT * FROM jobs WHERE id = :id", id=str(f["job_id"]))
        fp = fingerprint(orig["tool_id"], orig["target"], orig["params"], salt=f"retest:{uuid.uuid4()}")
        try:
            ips = deps.resolve_fn(orig["target"]["host"])
        except OSError:
            ips = []
        job_id = create_job(deps, conn, a, tool_id=orig["tool_id"], target=orig["target"], params=orig["params"],
                            resolved_ips=ips, fp=fp, plan_node_key=None, actor=f"user:{actor_id}",
                            retest_of=finding_id, requested_by=actor_id)
        conn.execute(text("INSERT INTO finding_retests (tenant_id, finding_id, job_id, requested_by, outcome) "
                          "VALUES (:t,:f,:j,:u,'pending')"),
                     {"t": str(tenant_id), "f": str(finding_id), "j": str(job_id), "u": str(actor_id)})
        audit.record(conn, tenant_id, f"user:{actor_id}", "finding.retest_requested",
                     {"finding_id": str(finding_id), "job_id": str(job_id)}, a["id"])
        st = row(conn, "SELECT status FROM jobs WHERE id = :id", id=str(job_id))["status"]
        if st == "DENIED":
            conn.execute(text("UPDATE finding_retests SET outcome='inconclusive', completed_at=now() WHERE job_id=:j"),
                         {"j": str(job_id)})
        if st == "AWAITING_APPROVAL" and a["status"] == "COMPLETED":
            transition_assessment(conn, tenant_id, a["id"], "RUNNING", "system:orchestrator", "retest")
            transition_assessment(conn, tenant_id, a["id"], "AWAITING_APPROVAL", "system:orchestrator", "retest approval")
        assessment_id = a["id"]
    advance(deps, tenant_id, assessment_id)
    return {"job_id": str(job_id), "job_status": st}


def cancel_assessment(deps: Deps, tenant_id, assessment_id, actor: str, reason: str = "cancelled by user") -> str:
    with _tx(deps, tenant_id) as conn:
        a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=str(assessment_id))
        if a is None:
            raise OrchestrationError("assessment not found", 404)
        if a["status"] in ASSESSMENT_TERMINAL or a["status"] == "CANCELLING":
            raise OrchestrationError(f"assessment is already {a['status']}")
        if a["status"] == "DRAFT":
            transition_assessment(conn, tenant_id, assessment_id, "CANCELLED", actor, reason)
            return "CANCELLED"
        transition_assessment(conn, tenant_id, assessment_id, "CANCELLING", actor, reason)
        for j in rows(conn, "SELECT id FROM jobs WHERE assessment_id = :a AND status IN "
                            "('PROPOSED','AWAITING_APPROVAL','QUEUED','FAILED','TIMED_OUT')", a=str(assessment_id)):
            try:
                transition_job(conn, tenant_id, j["id"], "CANCELLED", actor, reason)
            except IllegalTransition:
                pass
        conn.execute(text("UPDATE approvals SET status='INVALIDATED', reason='assessment cancelled' "
                          "WHERE assessment_id = :a AND status IN ('PENDING','APPROVED')"), {"a": str(assessment_id)})
    deps.r.set(bus.halt_key_assessment(str(assessment_id)), "cancelled", ex=86400)
    bus.publish_control(deps.r, {"type": "cancel_assessment", "tenant_id": str(tenant_id),
                                 "assessment_id": str(assessment_id), "reason": reason})
    return advance(deps, tenant_id, assessment_id) or "CANCELLING"


def emergency_stop(deps: Deps, tenant_id, actor_id, reason: str) -> dict:
    with _tx(deps, tenant_id) as conn:
        conn.execute(text("INSERT INTO tenant_controls (tenant_id, emergency_stop, stopped_by, stopped_at, reason) "
                          "VALUES (:t, true, :u, now(), :r) ON CONFLICT (tenant_id) DO UPDATE SET emergency_stop = true, "
                          "stopped_by = :u, stopped_at = now(), reason = :r"),
                     {"t": str(tenant_id), "u": str(actor_id), "r": reason})
        audit.record(conn, tenant_id, f"user:{actor_id}", "emergency_stop.activated", {"reason": reason})
        active = [r["id"] for r in rows(conn, "SELECT id FROM assessments WHERE status IN "
                                              "('PLANNING','RUNNING','AWAITING_APPROVAL','REPORTING')")]
    deps.r.set(bus.halt_key_tenant(str(tenant_id)), "1")
    bus.publish_control(deps.r, {"type": "emergency_stop", "tenant_id": str(tenant_id), "reason": reason})
    for aid in active:
        try:
            cancel_assessment(deps, tenant_id, aid, f"user:{actor_id}", f"emergency stop: {reason}")
        except OrchestrationError:
            pass
    return {"stopped_assessments": [str(a) for a in active]}


def reset_emergency_stop(deps: Deps, tenant_id, actor_id) -> None:
    with _tx(deps, tenant_id) as conn:
        conn.execute(text("UPDATE tenant_controls SET emergency_stop = false WHERE tenant_id = :t"), {"t": str(tenant_id)})
        audit.record(conn, tenant_id, f"user:{actor_id}", "emergency_stop.reset", {})
    deps.r.delete(bus.halt_key_tenant(str(tenant_id)))


# --------------------------------------------------------------------------------------------- reaper

def reap(deps: Deps) -> int:
    """Recover from lost workers/results: overdue RUNNING jobs time out (bounded retry); stuck cancels finish."""
    grace = get_settings().dispatch_grace_seconds
    n = 0
    for tid in list_tenant_ids(deps.engine):
        touched: set = set()
        with _tx(deps, tid) as conn:
            for j in rows(conn, "SELECT j.*, a.status AS a_status FROM jobs j JOIN assessments a ON a.id = j.assessment_id "
                                "WHERE j.status = 'RUNNING' AND j.deadline_at < now() - make_interval(secs => :g) "
                                "FOR UPDATE OF j SKIP LOCKED", g=grace):
                if j["a_status"] == "CANCELLING":
                    transition_job(conn, tid, j["id"], "CANCELLED", "system:reaper", "no result after cancellation")
                else:
                    transition_job(conn, tid, j["id"], "TIMED_OUT", "system:reaper", "no result before deadline + grace")
                    a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=str(j["assessment_id"]))
                    _maybe_retry(conn, tid, a, j)
                touched.add(j["assessment_id"])
                n += 1
            for a in rows(conn, "SELECT id FROM assessments WHERE status IN ('RUNNING','AWAITING_APPROVAL','CANCELLING')"):
                touched.add(a["id"])
        for aid in touched:
            advance(deps, tid, aid)
    return n
