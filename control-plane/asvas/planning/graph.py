"""LangGraph planning graph (spec pp. 9-10, 64-66, 71-72).

    agent_discovery ──► agent_config_verifier ──► merge      (PL-10: each sub-agent sees only its tool sub-schema)
       │ (provider error / budget) ──► END (error recorded; assessment fails honestly)
       ▼
    validate ──(nothing valid, retries left)──► agent_discovery   (bounded: max 1 re-proposal per round)
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
from asvas.planning.agents import AGENTS, AgentSpec, tools_for
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
    cost_micros: int
    provider_name: str
    is_live_ai: bool
    proposal: dict[str, Any] | None
    proposals: dict[str, Any]
    accepted: list[dict[str, Any]]
    rejected: list[dict[str, Any]]
    error: str | None
    done: bool


def build_context(conn, assessment: dict, round_no: int) -> PlanningContext:
    observations = []
    for r in rows(conn, """
        SELECT j.tool_id, j.target, j.status, e.content, e.tenant_id, e.job_id, e.attempt, e.seq, e.enc_alg,
               e.kek_id, e.dek_wrapped FROM jobs j
        LEFT JOIN evidence e ON e.job_id = j.id AND e.attempt = j.attempt
        WHERE j.assessment_id = :a ORDER BY j.created_at, e.seq LIMIT 50""", a=str(assessment["id"])):
        obs: dict[str, Any] = {"tool_id": r["tool_id"], "target": r["target"], "status": r["status"]}
        if r["content"] is not None:
            import json

            from asvas.evidence import evidence_plaintext
            ex = json.loads(evidence_plaintext(r).decode())
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
    from asvas.longterm import get_memory
    try:
        prior = get_memory().recall(assessment["tenant_id"], "tools " + " ".join(policy["allowed_tools"]))
    except Exception:  # noqa: BLE001 - memory is advisory; planning never depends on it
        prior = []
    return PlanningContext(
        prior_assessments=prior,
        assessment_id=str(assessment["id"]), round=round_no, scope=assessment["scope"], policy=policy,
        tools=[t for t in catalog() if t["tool_id"] in policy["allowed_tools"]],
        observations=observations, executed=executed,
        remaining_tokens=max(0, policy["max_tokens"] - assessment["tokens_used"]))


def build_planner(engine: Engine | None, provider: ModelProvider,
                  materialize_fn: Callable[[Any, dict, PlanState], None],
                  resolve_fn: Callable[[str], list[str]] = resolve, checkpointer=None,
                  blocked_fn: Callable[[str], set[str]] = lambda _aid: set()):
    tx = functools.partial(tenant_tx, engine=engine)

    def budget_error(a: dict, state: PlanState) -> str | None:
        policy = a["testing_policy"]
        used = a["tokens_used"] + state.get("tokens", 0)
        if provider.is_live_ai and used >= policy["max_tokens"]:
            return f"token budget exhausted ({used}/{policy['max_tokens']})"
        spent = a.get("cost_usd_micros", 0) + state.get("cost_micros", 0)
        cap = policy.get("max_cost_usd_cents", 200) * 10_000
        if provider.is_live_ai and spent >= cap:
            return f"cost budget exhausted (${spent / 1e6:.4f} of ${cap / 1e6:.2f})"
        started = a["started_at"]
        if started and dt.datetime.now(dt.UTC) - started > dt.timedelta(minutes=policy["max_wall_clock_minutes"]):
            return "wall-clock budget exhausted"
        return None

    def make_agent(agent: AgentSpec):
        def run_agent(state: PlanState) -> PlanState:
            if state.get("error"):
                return {}
            with tx(state["tenant_id"]) as conn:
                a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=state["assessment_id"])
                if a is None:
                    raise LookupError(f"assessment {state['assessment_id']} not found")
                if err := budget_error(a, state):
                    return {"error": err}
                ctx = build_context(conn, a, state["round"])
            ctx.blocked_paths = sorted(blocked_fn(state["assessment_id"]))
            ctx.tools = tools_for(agent, ctx.tools)
            ctx.agent, ctx.agent_brief = agent.name, agent.brief
            prev = dict(state.get("proposals") or {})
            if not ctx.tools:  # this agent has nothing it may use under the testing policy
                prev[agent.name] = {"steps": [], "done": True, "summary": "no tools in this agent's sub-schema"}
                return {"proposals": prev}
            try:
                res = provider.propose(ctx)
            except ProviderError as e:
                return {"error": f"planning provider '{provider.name}' failed ({agent.name} agent): {e}",
                        "provider_name": provider.name, "is_live_ai": provider.is_live_ai}
            prev[agent.name] = _tag(res.proposal.model_dump(), agent)
            return {"proposals": prev, "tokens": state.get("tokens", 0) + res.tokens_used,
                    "cost_micros": state.get("cost_micros", 0) + round(res.cost_usd * 1_000_000),
                    "provider_name": res.provider_name, "is_live_ai": res.is_live_ai}
        return run_agent

    def merge(state: PlanState) -> PlanState:
        props = state.get("proposals") or {}
        steps = [s for p in props.values() for s in p["steps"]]
        done = all(p.get("done") for p in props.values()) if props else True
        return {"proposal": {"steps": steps, "done": done,
                             "summary": " | ".join(f"{k}: {v.get('summary', '')}" for k, v in props.items())},
                "done": done, "error": None, "proposals": {}}

    def validate(state: PlanState) -> PlanState:
        with tx(state["tenant_id"]) as conn:
            a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=state["assessment_id"])
            if a is None:
                raise LookupError(f"assessment {state['assessment_id']} not found")
            fps = {r["fingerprint"] for r in rows(conn, "SELECT fingerprint FROM jobs WHERE assessment_id = :a",
                                                  a=state["assessment_id"])}
            count = len(fps)
        proposal = PlanProposal.model_validate({**state["proposal"], "steps": [
            {k: v for k, v in st.items() if k != "agent"} for st in state["proposal"]["steps"]]})
        agent_of = {st["step_id"]: st.get("agent") for st in state["proposal"]["steps"]}
        outcome = validate_proposal(proposal, Scope.model_validate(a["scope"]), a["testing_policy"], fps, count,
                                    state["round"], resolve_fn, blocked_fn(state["assessment_id"]), agent_of)
        return {
            "accepted": [{"step": {**v.step.model_dump(), "agent": agent_of.get(v.step.step_id)},
                          "target": v.target, "params": v.params,
                          "resolved_ips": v.resolved_ips, "fingerprint": v.fingerprint, "depth": v.depth}
                         for v in outcome.accepted],
            "rejected": state.get("rejected", []) + [{"step": {**s.model_dump(), "agent": agent_of.get(s.step_id)},
                                                       "reasons": r} for s, r in outcome.rejected],
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
            if a is None:
                raise LookupError(f"assessment {state['assessment_id']} not found")
            materialize_fn(conn, a, state)
        return {}

    g = StateGraph(PlanState)
    names = [f"agent_{a.name}" for a in AGENTS]
    for a, n in zip(AGENTS, names, strict=True):
        g.add_node(n, make_agent(a))
    g.add_node("merge", merge)
    g.add_node("validate", validate)
    g.add_node("repropose", bump)
    g.add_node("materialize", materialize)
    g.add_edge(START, names[0])
    for cur, nxt in zip(names, [*names[1:], "merge"], strict=True):
        g.add_conditional_edges(cur, lambda s, nxt=nxt: END if s.get("error") else nxt, [nxt, END])
    g.add_edge("merge", "validate")
    g.add_conditional_edges("validate", route_after_validate, ["repropose", "materialize"])
    g.add_edge("repropose", names[0])
    g.add_edge("materialize", END)
    return g.compile(checkpointer=checkpointer)


def _tag(proposal: dict, agent: AgentSpec) -> dict:
    """Namespace step ids per agent (ids stay unique across agents) and record which agent proposed each step.
    The agent label is set here, never taken from model output."""
    def nid(x: str) -> str:
        return f"{agent.prefix}-{x[:35]}"
    for st in proposal["steps"]:
        st["step_id"], st["depends_on"] = nid(st["step_id"]), [nid(d) for d in st["depends_on"]]
        st["agent"] = agent.name
    return proposal


def record_planning_audit(conn, tenant_id, assessment_id, state: PlanState) -> None:
    audit.record(conn, tenant_id, "system:planner", "planning.round", {
        "round": state["round"], "provider": state.get("provider_name"), "is_live_ai": state.get("is_live_ai"),
        "accepted": len(state.get("accepted", [])), "rejected": len(state.get("rejected", [])),
        "agents": sorted({x["step"].get("agent") for x in state.get("accepted", []) + state.get("rejected", [])
                          if x["step"].get("agent")}),
        "rejections": [{"tool_id": r["step"]["tool_id"], "agent": r["step"].get("agent"), "target": r["step"]["target"],
                        "reasons": r["reasons"]}
                       for r in state.get("rejected", [])],
        "tokens": state.get("tokens", 0), "cost_usd": state.get("cost_micros", 0) / 1e6, "done": state.get("done"),
    }, assessment_id)
