"""PL-10: specialised sub-agents, each restricted to its own tool sub-schema."""

from __future__ import annotations

from asvas.db import rows, tenant_tx
from asvas.orchestration import engine
from asvas.planning.agents import AGENTS, tool_allowed_for
from asvas.planning.providers import PlanProposal, PlanStep, ProposedTarget, ProviderResult
from tests.test_lifecycle import jobs_of, tid_of


class Spy:
    """Records what each agent was shown; every agent greedily proposes every tool it knows about (all of them)."""
    name, is_live_ai = "spy", False

    def __init__(self):
        self.seen: dict[str, list[str]] = {}

    def propose(self, ctx):
        self.seen[ctx.agent] = sorted(t["tool_id"] for t in ctx.tools)
        steps = [PlanStep(step_id=f"s{i}", tool_id=t, target=ProposedTarget(scheme="http", host="127.0.0.1", port=18080),
                          params={"path": "/"} if t != "tls.configuration" else {}, rationale="greedy")
                 for i, t in enumerate(["http.security_headers", "http.allowed_methods"])]
        return ProviderResult(PlanProposal(steps=steps, done=True, summary=ctx.agent), 0, self.name, False)


def test_registry_roles_cover_agents():
    assert {a.role for a in AGENTS} == {"RECON", "CONFIG_VERIFIER"}
    assert tool_allowed_for("discovery", "http.allowed_methods")
    assert not tool_allowed_for("discovery", "http.security_headers")
    assert tool_allowed_for("config_verifier", "tls.configuration")
    assert not tool_allowed_for(None, "http.security_headers")


def test_each_agent_sees_and_may_use_only_its_sub_schema(client, make_assessment, deps):
    spy = Spy()
    deps.provider_factory = lambda: spy
    a = make_assessment(ports=(18080,), tools=("http.security_headers", "http.allowed_methods"), approval=("high",))
    op = client.as_user("operator@acme.test")
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 202
    engine.run_planning_round(deps, tid_of(), a["id"])
    assert spy.seen == {"discovery": ["http.allowed_methods"], "config_verifier": ["http.security_headers"]}
    jobs = sorted(j["tool_id"] for j in jobs_of(a["id"]))
    # exactly one job per tool: each from the agent whose role owns it; cross-role proposals were rejected
    assert jobs == ["http.allowed_methods", "http.security_headers"]
    with tenant_tx(tid_of()) as conn:
        nodes = rows(conn, "SELECT status, reasons, data FROM plan_nodes WHERE assessment_id = :a AND kind = 'step'",
                     a=a["id"])
        ev = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'planning.round'")[0]["data"]
    rejected = [n for n in nodes if n["status"] == "rejected"]
    assert len(rejected) == 2 and all(any("sub-schema" in r for r in n["reasons"]) for n in rejected)
    accepted_agents = {n["data"]["agent"] for n in nodes if n["status"] != "rejected"}
    assert accepted_agents == {"discovery", "config_verifier"}
    assert ev["agents"] == ["config_verifier", "discovery"]


def test_agent_without_tools_is_not_called(client, make_assessment, deps):
    spy = Spy()
    deps.provider_factory = lambda: spy
    a = make_assessment(ports=(18080,), tools=("http.security_headers",))
    op = client.as_user("operator@acme.test")
    client.post(f"/api/v1/assessments/{a['id']}/start", headers=op)
    engine.run_planning_round(deps, tid_of(), a["id"])
    assert set(spy.seen) == {"config_verifier"}
