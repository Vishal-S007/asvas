"""LangGraph planning graph (spec pp. 9-10, 64-66, 71-72).

    propose ──(provider error / budget)──► END (error recorded; assessment fails honestly)
       │
       ▼
    validate ──(nothing valid, retries left)──► propose      (bounded: max 1 re-proposal per round)
       │
       ▼
    materialize (OPA decision per step → job DENIED | AWAITING_APPROVAL | QUEUED) ──► END

The graph is a fixed DAG with one bounded back-edge; it never executes tools itself.
Checkpoints are persisted in PostgreSQL (thread = assessment:round) when a checkpointer is supplied.
"""

from __future__ import annotations

import datetime as dt
import functools
from collections.abc import Callable
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from sqlalchemy import Engine

from asvas import audit
from asvas.db import row, rows, tenant_tx
from asvas.planning.providers import ModelProvider, PlanningContext, PlanProposal, ProviderError
from asvas.planning.validate import validate_proposal
from asvas.redaction import untrusted_snippet
from asvas.scope import Scope, resolve
from asvas.tools import catalog

MAX_REPROPOSALS = 1


class PlanState(TypedDict, total=False):
    tenant_id: str
    assessment_id: str
    round: int
    attempts: int
    tokens: int
    provider_name: str
    is_live_ai: bool
    proposal: dict[str, Any] | None
    accepted: list[dict[str, Any]]
    rejected: list[dict[str, Any]]
    error: str | None
    done: bool


def build_context(conn, assessment: dict, round_no: int) -> PlanningContext:
    observations = []
    for r in rows(conn, """
        SELECT j.tool_id, j.target, j.status, e.content FROM jobs j
        LEFT JOIN evidence e ON e.job_id = j.id AND e.attempt = j.attempt
        WHERE j.assessment_id = :a ORDER BY j.created_at, e.seq LIMIT 50""", a=str(assessment["id"])):
        obs: dict[str, Any] = {"tool_id": r["tool_id"], "target": r["target"], "status": r["status"]}
        if r["content"] is not None:
            import json
            ex = json.loads(bytes(r["content"]).decode())
            resp = ex.get("response") or {}
            hdrs = {k.lower(): v for k, v in resp.get("headers", [])}
            obs.update({"http_status": resp.get("status"),
                        "server_header": untrusted_snippet(hdrs.get("server")),
                        "allow_header": untrusted_snippet(hdrs.get("allow")),
                        "body_excerpt": untrusted_snippet(resp.get("body_excerpt"), 200)})
        observations.append(obs)
    executed = [{"tool_id": r["tool_id"], "target": r["target"], "params": r["params"]}
                for r in rows(conn, "SELECT tool_id, target, params FROM jobs WHERE assessment_id = :a",
                              a=str(assessment["id"]))]
    policy = assessment["testing_policy"]
    return PlanningContext(
        assessment_id=str(assessment["id"]), round=round_no, scope=assessment["scope"], policy=policy,
        tools=[t for t in catalog() if t["tool_id"] in policy["allowed_tools"]],
        observations=observations, executed=executed,
        remaining_tokens=max(0, policy["max_tokens"] - assessment["tokens_used"]))


def build_planner(engine: Engine | None, provider: ModelProvider,
                  materialize_fn: Callable[[Any, dict, PlanState], None],
                  resolve_fn: Callable[[str], list[str]] = resolve, checkpointer=None):
    tx = functools.partial(tenant_tx, engine=engine)

    def propose(state: PlanState) -> PlanState:
        with tx(state["tenant_id"]) as conn:
            a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=state["assessment_id"])
            assert a is not None
            policy = a["testing_policy"]
            used = a["tokens_used"] + state.get("tokens", 0)
            if provider.is_live_ai and used >= policy["max_tokens"]:
                return {"error": f"token budget exhausted ({used}/{policy['max_tokens']})"}
            started = a["started_at"]
            if started and dt.datetime.now(dt.UTC) - started > dt.timedelta(minutes=policy["max_wall_clock_minutes"]):
                return {"error": "wall-clock budget exhausted"}
            ctx = build_context(conn, a, state["round"])
        try:
            res = provider.propose(ctx)
        except ProviderError as e:
            return {"error": f"planning provider '{provider.name}' failed: {e}",
                    "provider_name": provider.name, "is_live_ai": provider.is_live_ai}
        return {"proposal": res.proposal.model_dump(), "tokens": state.get("tokens", 0) + res.tokens_used,
                "provider_name": res.provider_name, "is_live_ai": res.is_live_ai, "error": None,
                "done": res.proposal.done}

    def validate(state: PlanState) -> PlanState:
        with tx(state["tenant_id"]) as conn:
            a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=state["assessment_id"])
            assert a is not None
            fps = {r["fingerprint"] for r in rows(conn, "SELECT fingerprint FROM jobs WHERE assessment_id = :a",
                                                  a=state["assessment_id"])}
            count = len(fps)
        proposal = PlanProposal.model_validate(state["proposal"])
        outcome = validate_proposal(proposal, Scope.model_validate(a["scope"]), a["testing_policy"], fps, count,
                                    state["round"], resolve_fn)
        return {
            "accepted": [{"step": v.step.model_dump(), "target": v.target, "params": v.params,
                          "resolved_ips": v.resolved_ips, "fingerprint": v.fingerprint, "depth": v.depth}
                         for v in outcome.accepted],
            "rejected": state.get("rejected", []) + [{"step": s.model_dump(), "reasons": r} for s, r in outcome.rejected],
        }

    def route_after_validate(state: PlanState) -> str:
        if not state.get("accepted") and state.get("rejected") and not state.get("done") \
                and state.get("attempts", 0) < MAX_REPROPOSALS:
            return "repropose"
        return "materialize"

    def bump(state: PlanState) -> PlanState:
        return {"attempts": state.get("attempts", 0) + 1}

    def materialize(state: PlanState) -> PlanState:
        with tx(state["tenant_id"]) as conn:
            a = row(conn, "SELECT * FROM assessments WHERE id = :id FOR UPDATE", id=state["assessment_id"])
            assert a is not None
            materialize_fn(conn, a, state)
        return {}

    g = StateGraph(PlanState)
    g.add_node("propose", propose)
    g.add_node("validate", validate)
    g.add_node("repropose", bump)
    g.add_node("materialize", materialize)
    g.add_edge(START, "propose")
    g.add_conditional_edges("propose", lambda s: END if s.get("error") else "validate", ["validate", END])
    g.add_conditional_edges("validate", route_after_validate, ["repropose", "materialize"])
    g.add_edge("repropose", "propose")
    g.add_edge("materialize", END)
    return g.compile(checkpointer=checkpointer)


def record_planning_audit(conn, tenant_id, assessment_id, state: PlanState) -> None:
    audit.record(conn, tenant_id, "system:planner", "planning.round", {
        "round": state["round"], "provider": state.get("provider_name"), "is_live_ai": state.get("is_live_ai"),
        "accepted": len(state.get("accepted", [])), "rejected": len(state.get("rejected", [])),
        "rejections": [{"tool_id": r["step"]["tool_id"], "target": r["step"]["target"], "reasons": r["reasons"]}
                       for r in state.get("rejected", [])],
        "tokens": state.get("tokens", 0), "done": state.get("done"),
    }, assessment_id)
