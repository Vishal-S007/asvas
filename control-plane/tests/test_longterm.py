"""DA-04: Qdrant long-term memory — anonymised, tenant-isolated, optional. Runs against the local Qdrant started by
scripts/qdrant-dev.sh (skips if it is not running); the disabled path always runs."""

from __future__ import annotations

import socket
import uuid
from pathlib import Path

import httpx
import pytest

from asvas import longterm
from asvas.config import get_settings
from asvas.db import rows, tenant_tx
from asvas.orchestration import engine
from tests.test_lifecycle import jobs_of, result, start, tid_of

ROOT = Path(__file__).resolve().parents[2]
KEY = ROOT / "var" / "qdrant" / "api-key"
CA = ROOT / "var" / "certs" / "ca.crt"


def _up() -> bool:
    try:
        socket.create_connection(("127.0.0.1", 6333), timeout=0.5).close()
        return KEY.exists()
    except OSError:
        return False


live = pytest.mark.skipif(not _up(), reason="local Qdrant not running (scripts/qdrant-dev.sh start)")


@pytest.fixture()
def mem(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "qdrant_url", "https://localhost:6333")
    monkeypatch.setattr(s, "qdrant_api_key_file", str(KEY))
    monkeypatch.setattr(s, "qdrant_ca_file", str(CA))
    longterm.get_memory.cache_clear()
    yield longterm.get_memory()
    longterm.get_memory.cache_clear()


def _summary(rule="HDR-CSP"):
    return {"text": f"tools http.security_headers services 1 findings {rule} CWE-693 low confirmed",
            "tools": ["http.security_headers"], "rules": [{"rule_id": rule, "severity": "low"}], "services": 1}


def test_embedding_is_deterministic_and_normalised():
    a, b = longterm.embed("tools http.security_headers"), longterm.embed("tools http.security_headers")
    assert a == b and len(a) == 256 and abs(sum(x * x for x in a) - 1) < 1e-9


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr(get_settings(), "qdrant_url", "")
    longterm.get_memory.cache_clear()
    m = longterm.get_memory()
    assert m.name == "disabled" and m.recall("t", "x") == [] and m.health() == {"enabled": False}
    longterm.get_memory.cache_clear()


@live
def test_tenant_isolation(mem):
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    try:
        mem.remember(t1, uuid.uuid4(), _summary("HDR-CSP"))
        mem.remember(t2, uuid.uuid4(), _summary("TLS-LEGACY"))
        r1 = mem.recall(t1, "tools http.security_headers")
        r2 = mem.recall(t2, "tools http.security_headers")
        assert [x["rules"][0]["rule_id"] for x in r1] == ["HDR-CSP"]
        assert [x["rules"][0]["rule_id"] for x in r2] == ["TLS-LEGACY"]
        assert mem.recall(uuid.uuid4(), "tools http.security_headers") == []
    finally:
        mem.forget_tenant(t1)
        mem.forget_tenant(t2)
    assert mem.recall(t1, "tools") == []


@live
def test_requires_api_key():
    r = httpx.get("https://localhost:6333/collections", verify=str(CA))
    assert r.status_code == 401


def test_foreign_tenant_point_dropped_even_if_store_returns_it():
    def handler(req):
        if req.url.path.endswith("/points/search"):
            return httpx.Response(200, json={"result": [
                {"score": 0.9, "payload": {"tenant_id": "other", "tools": [], "rules": []}},
                {"score": 0.8, "payload": {"tenant_id": "mine", "tools": ["x"], "rules": []}}]})
        return httpx.Response(200, json={"result": {}})
    m = longterm.LongTermMemory("https://q", None, None, transport=httpx.MockTransport(handler))
    assert m.recall("mine", "q") == [{"score": 0.8, "tools": ["x"], "rules": []}]


@live
def test_completed_assessment_is_remembered_anonymised_and_recalled(client, make_assessment, deps, mem):
    try:
        aid, op = start(client, make_assessment, deps, ports=(18080,))
        [job] = jobs_of(aid)
        engine.ingest_result(deps, result(job))
        with tenant_tx(tid_of()) as conn:
            ev = rows(conn, "SELECT event_type, data FROM audit_events WHERE event_type LIKE 'memory.%'")
        assert [e["event_type"] for e in ev] == ["memory.stored"], ev
        text = ev[0]["data"]["anonymised_text"]
        assert "127.0.0.1" not in text and "18080" not in text and "http://" not in text and "HDR-CSP" in text
        got = mem.recall(tid_of(), "tools http.security_headers")
        assert got and any(r["rule_id"] == "HDR-CSP" for r in got[0]["rules"])
        # planner context of the next assessment in the same tenant includes it
        from asvas.planning.graph import build_context
        a2 = make_assessment()
        with tenant_tx(tid_of()) as conn:
            a = rows(conn, "SELECT * FROM assessments WHERE id = :a", a=a2["id"])[0]
            ctx = build_context(conn, a, 0)
        assert ctx.prior_assessments and "rules" in ctx.prior_assessments[0]
    finally:
        mem.forget_tenant(tid_of())


def test_anonymisation_guard_rejects_identifiers(monkeypatch):
    class C:
        pass
    calls = iter([[{"tool_id": "http.security_headers"}],
                  [{"rule_id": "X", "cwe": "host.example.com", "severity": "low", "verification_status": "c", "n": 1}],
                  [{"n": 1}]])
    monkeypatch.setattr(longterm, "rows", lambda *a, **k: next(calls))
    with pytest.raises(ValueError, match="anonymisation"):
        longterm.summarise(C(), "a")
