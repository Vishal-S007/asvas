"""PL-09 cost limits, PL-05 path blocking after consecutive failures, DA-05 short-term memory erasure."""

from __future__ import annotations

import json

import httpx
import pytest

from asvas.config import get_settings
from asvas.db import rows, tenant_tx
from asvas.orchestration import engine, memory
from asvas.planning.providers import AnthropicProvider, PlanProposal, ProviderError, cap_output_tokens
from asvas.planning.validate import path_id, validate_proposal
from tests.test_lifecycle import jobs_of, result, start, tid_of
from tests.test_planning import _ctx, _live, _policy, _scope, step


def _reply(steps, usage):
    return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(
        {"steps": steps, "done": True, "summary": "ok"})}], "usage": usage})


# ----------------------------------------------------------------------------------------------- PL-09
def test_live_provider_refuses_without_prices(monkeypatch):
    _live(monkeypatch)
    monkeypatch.setattr(get_settings(), "model_input_usd_per_mtok", None)
    called = []
    with pytest.raises(ProviderError, match="pricing is not configured"):
        AnthropicProvider(transport=httpx.MockTransport(lambda r: called.append(r) or _reply([], {}))).propose(_ctx())
    assert called == []  # refused before any model call


def test_cost_is_computed_and_max_tokens_capped(monkeypatch):
    _live(monkeypatch, pin=3.0, pout=15.0)
    sent = {}

    def handler(req):
        sent.update(json.loads(req.content))
        return _reply([step("s1")], {"input_tokens": 1000, "output_tokens": 200})
    res = AnthropicProvider(transport=httpx.MockTransport(handler)).propose(_ctx())
    assert res.cost_usd == pytest.approx((1000 * 3 + 200 * 15) / 1e6)
    assert sent["max_tokens"] <= 2048


def test_step_that_could_exceed_limit_is_refused(monkeypatch):
    _live(monkeypatch, pin=3.0, pout=15.0)
    monkeypatch.setattr(get_settings(), "max_cost_per_step_usd", 0.01)
    # 0.01 USD - prompt worst case leaves < 256 output tokens at $15/Mtok
    with pytest.raises(ProviderError, match="per-step cost limit"):
        cap_output_tokens("x" * 3000, 2048)
    assert cap_output_tokens("x" * 100, 2048) == min(2048, int((0.01 - 100 * 3 / 1e6) / 15 * 1e6))


def test_actual_cost_over_limit_is_an_error(monkeypatch):
    _live(monkeypatch, pin=3.0, pout=15.0)
    monkeypatch.setattr(get_settings(), "max_cost_per_step_usd", 0.05)
    with pytest.raises(ProviderError, match="exceeded the per-step limit"):
        AnthropicProvider(transport=httpx.MockTransport(
            lambda r: _reply([step("s1")], {"input_tokens": 20000, "output_tokens": 1000}))).propose(_ctx())


def test_per_step_limit_cannot_be_raised_above_spec():
    from asvas.config import Settings
    with pytest.raises(ValueError):
        Settings(max_cost_per_step_usd=0.75)


def test_assessment_cost_budget_stops_planning(client, make_assessment, deps):
    class Pricey:
        name, is_live_ai = "fake-live", True

        def propose(self, ctx):
            from asvas.planning.providers import ProviderResult
            return ProviderResult(PlanProposal(steps=[], done=False, summary="x"), 10, self.name, True, 0.30)
    deps.provider_factory = Pricey
    a = make_assessment(max_cost_usd_cents=25)
    op = client.as_user("operator@acme.test")
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 202
    engine.run_planning_round(deps, tid_of(), a["id"])
    got = client.get(f"/api/v1/assessments/{a['id']}", headers=op).json()
    with tenant_tx(tid_of()) as conn:
        spent = rows(conn, "SELECT cost_usd_micros FROM assessments WHERE id = :a", a=a["id"])[0]["cost_usd_micros"]
    assert spent == 300_000
    if got["status"] == "PLANNING":
        engine.run_planning_round(deps, tid_of(), a["id"])
        got = client.get(f"/api/v1/assessments/{a['id']}", headers=op).json()
    assert got["status"] == "FAILED"
    with tenant_tx(tid_of()) as conn:
        ev = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'assessment.transition' "
                        "ORDER BY id DESC LIMIT 1")
    assert ev and "cost budget exhausted" in json.dumps(ev[0]["data"])


# ----------------------------------------------------------------------------------------------- PL-05
def test_validator_rejects_blocked_path():
    s = step("s1")
    blocked = {path_id("http.security_headers", {"scheme": "http", "host": "127.0.0.1", "port": 18080})}
    out = validate_proposal(PlanProposal.model_validate({"steps": [s], "done": True, "summary": ""}), _scope(),
                            _policy(), set(), 0, 0, lambda h: ["127.0.0.1"], blocked)
    assert not out.accepted and "3 consecutive failures" in out.rejected[0][1][0]


def test_three_consecutive_failures_block_path(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,), max_attempts=3)
    for attempt in (1, 2, 3):
        [job] = jobs_of(aid)
        assert job["attempt"] == attempt and job["status"] == "RUNNING"
        assert engine.ingest_result(deps, result(job, status="FAILED", exchanges=[], error="boom")) == "ok"
        if attempt < 3:
            engine.advance(deps, tid_of(), aid)
    [job] = jobs_of(aid)
    assert job["status"] == "FAILED"  # no further retry
    path = path_id(job["tool_id"], job["target"])
    with tenant_tx(tid_of()) as conn:
        ev = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'plan.path_blocked'")
    assert ev and ev[0]["data"]["path"] == path and ev[0]["data"]["consecutive_failures"] == 3


def test_success_resets_failure_counter(deps):
    memory.record_failure(deps.r, "a1", "p", 30)
    memory.record_failure(deps.r, "a1", "p", 30)
    memory.reset_failures(deps.r, "a1", "p")
    assert memory.record_failure(deps.r, "a1", "p", 30) == 1


# ----------------------------------------------------------------------------------------------- DA-05
def test_short_term_memory_has_ttl_and_is_erased_at_end(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    ks = memory.keys(deps.r, aid)
    assert any(k.endswith(":notes") for k in ks)
    assert all(0 < deps.r.ttl(k) <= 30 * 60 + 3600 for k in ks)
    [job] = jobs_of(aid)
    engine.ingest_result(deps, result(job))
    for _ in range(6):
        engine.advance(deps, tid_of(), aid)
        engine.run_planning_round(deps, tid_of(), aid)
        for j in jobs_of(aid):
            if j["status"] == "RUNNING":
                engine.ingest_result(deps, result(j))
    st = client.get(f"/api/v1/assessments/{aid}", headers=op).json()["status"]
    assert st == "COMPLETED"
    assert memory.keys(deps.r, aid) == []
