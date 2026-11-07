"""End-to-end tests with the real Go executor, real OPA, Redis Streams and the local test target.

Marked `integration`; they need: built executor (Go >= 1.26), OPA binary, PostgreSQL, Redis.
"""

import json
import os
import time

import pytest
from sqlalchemy import text

from asvas.db import rows, tenant_tx
from asvas.orchestration import bus
from asvas.planning.providers import PlanProposal, ProviderResult
from tests.conftest import wait_status
from tests.test_lifecycle import jobs_of, tid_of

pytestmark = pytest.mark.integration


class Scripted:
    name, is_live_ai = "scripted-test", False

    def __init__(self, port, paths):
        self.port, self.paths = port, paths

    def __call__(self):
        return self

    def propose(self, ctx):
        steps = [{"step_id": f"s{i}", "tool_id": "http.security_headers",
                  "target": {"scheme": "http", "host": "127.0.0.1", "port": self.port},
                  "params": {"path": p}, "rationale": "scripted", "depends_on": []} for i, p in enumerate(self.paths)]
        return ProviderResult(PlanProposal(steps=steps if ctx.round == 0 else [], done=True, summary="scripted"),
                              0, self.name, False)


def _start(client, make_assessment, **kw):
    a = make_assessment(**kw)
    op = client.as_user("operator@acme.test")
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 202
    return a["id"], op


def _findings(client, op, aid):
    return {f["rule_id"]: f for f in client.get(f"/api/v1/assessments/{aid}/findings", headers=op).json()}


def test_complete_local_assessment_workflow(client, make_assessment, deps, executor, target_server, orchestrator):
    weak, hard = target_server["weak"], target_server["hardened"]
    aid, op = _start(client, make_assessment, ports=(weak, hard),
                     tools=("http.security_headers", "http.allowed_methods"), approval=("medium", "high"))
    wait_status(client, op, aid, {"AWAITING_APPROVAL"}, 60)
    apr = client.as_user("approver@acme.test")
    pend = [x for x in client.get("/api/v1/approvals?status=PENDING", headers=apr).json() if x["assessment_id"] == aid]
    assert len(pend) == 2
    for x in pend:
        r = client.post(f"/api/v1/approvals/{x['id']}/decision",
                        json={"decision": "approve", "binding_hash": x["binding_hash"]}, headers=apr)
        assert r.status_code == 200, r.text
    a = wait_status(client, op, aid, {"COMPLETED", "FAILED"}, 60)
    assert a["status"] == "COMPLETED", a
    assert a["job_counts"] == {"SUCCEEDED": 4}
    f = _findings(client, op, aid)
    assert set(f) == {"HDR-XCTO", "HDR-CSP", "HDR-FRAME", "COOKIE-FLAGS", "BANNER-VERSION", "METHODS-ADVERTISED"}
    assert all(x["asset"] == f"http://127.0.0.1:{weak}" for x in f.values())  # hardened port: no findings
    assert f["BANNER-VERSION"]["verification_status"] == "suspected"
    assert f["METHODS-ADVERTISED"]["verification_status"] == "suspected"
    # Evidence integrity + linkage; injected banner is stored only as evidence data.
    ev = client.get(f"/api/v1/evidence/{f['BANNER-VERSION']['evidence_ids'][0]}", headers=op).json()
    assert ev["integrity_ok"] and "ignore all previous instructions" in json.dumps(ev["content"])
    # Injection did not create any job against other targets.
    assert {(j["target"]["host"], j["target"]["port"]) for j in jobs_of(aid)} <= {("127.0.0.1", weak), ("127.0.0.1", hard)}
    # Executor-side policy decision and sandbox attestation were recorded.
    tl = client.get(f"/api/v1/assessments/{aid}/timeline", headers=op).json()
    results = [e["data"] for e in tl if e["event_type"] == "tool.result"]
    assert len(results) == 4 and all(r["executor_policy"]["allow"] and r["executor_policy"]["plane"] == "execution"
                                     for r in results)
    att = results[0]["sandbox_attestation"]
    assert att["nonewprivs"] == "1"
    if os.geteuid() == 0:
        assert int(att["uid"]) >= 62000 and att["capeff"] == "0000000000000000"
        assert results[0]["egress_mode"].startswith("nftables")
    assert client.get("/api/v1/audit/verify", headers=op).json()["ok"]


def test_redirects_validated(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/redirect-out", "/redirect-in"])
    aid, op = _start(client, make_assessment, ports=(weak,))
    wait_status(client, op, aid, {"COMPLETED"}, 60)
    with tenant_tx(tid_of()) as conn:
        evs = [json.loads(bytes(r["content"])) for r in rows(conn, "SELECT content FROM evidence ORDER BY job_id, seq")]
    blocked = [e for e in evs if (e.get("redirect") or {}).get("decision") == "blocked"]
    followed = [e for e in evs if (e.get("redirect") or {}).get("decision") == "followed"]
    assert len(blocked) == 1 and "198.51.100.7" in blocked[0]["redirect"]["location"]
    assert "outside the validated scope" in blocked[0]["redirect"]["reason"]
    assert all(e["request"]["host"] != "198.51.100.7" for e in evs)  # never contacted
    assert len(followed) == 1 and any(e["request"]["path"] == "/" and e["seq"] == 1 for e in evs)


def test_worker_timeout_is_bounded(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/slow"])
    t0 = time.time()
    aid, op = _start(client, make_assessment, ports=(weak,), job_timeout_seconds=5, max_attempts=1)
    wait_status(client, op, aid, {"COMPLETED", "FAILED"}, 40)
    [job] = jobs_of(aid)
    assert job["status"] == "TIMED_OUT" and time.time() - t0 < 30
    assert job["attempt"] == 1


def test_cancellation_kills_running_worker(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/slow"])
    aid, op = _start(client, make_assessment, ports=(weak,), job_timeout_seconds=30)
    wait_status(client, op, aid, {"RUNNING"}, 30)
    time.sleep(1.0)  # let the sandbox child start its request
    t0 = time.time()
    r = client.post(f"/api/v1/assessments/{aid}/cancel", json={"reason": "test cancel"}, headers=op)
    assert r.status_code == 202
    a = wait_status(client, op, aid, {"CANCELLED"}, 15)
    assert time.time() - t0 < 10, "cancellation must not wait for the 30 s job timeout"
    [job] = jobs_of(aid)
    assert job["status"] == "CANCELLED" and "killed" in (job["error"] or "")
    assert a["status"] == "CANCELLED"


def test_emergency_stop_kills_running_worker(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/slow"])
    aid, op = _start(client, make_assessment, ports=(weak,), job_timeout_seconds=30)
    wait_status(client, op, aid, {"RUNNING"}, 30)
    time.sleep(1.0)
    r = client.post("/api/v1/system/emergency-stop", json={"reason": "drill"}, headers=client.as_user("admin@acme.test"))
    assert r.status_code == 200
    wait_status(client, op, aid, {"CANCELLED"}, 15)
    assert jobs_of(aid)[0]["status"] == "CANCELLED"


def test_duplicate_job_delivery_executes_once(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/"])
    aid, op = _start(client, make_assessment, ports=(weak,))
    wait_status(client, op, aid, {"COMPLETED"}, 40)
    # Re-deliver the exact signed envelope (at-least-once delivery / replay).
    for _, fields in deps.r.xrange(bus.JOBS):
        deps.r.xadd(bus.JOBS, fields)
    time.sleep(3)
    with tenant_tx(tid_of()) as conn:
        assert conn.execute(text("SELECT count(*) FROM job_results")).scalar() == 1
        assert conn.execute(text("SELECT count(*) FROM audit_events WHERE event_type='tool.result'")).scalar() == 1
    assert deps.r.xlen(bus.RESULTS) == 1  # the executor did not run it again


def test_retest_marks_resolved(client, make_assessment, deps, executor, target_server, orchestrator):
    weak = target_server["weak"]
    aid, op = _start(client, make_assessment, ports=(weak,))
    wait_status(client, op, aid, {"COMPLETED"}, 40)
    f = _findings(client, op, aid)["HDR-XCTO"]
    target_server["fixed_flag"].write_text("1")  # operator "fixes" the target
    try:
        r = client.post(f"/api/v1/findings/{f['id']}/retest", headers=op)
        assert r.status_code == 202, r.text
        time.sleep(0.5)
        wait_status(client, op, aid, {"COMPLETED"}, 40)
        f2 = _findings(client, op, aid)["HDR-XCTO"]
        assert f2["state"] == "resolved"
        assert [x["outcome"] for x in f2["retests"]] == ["resolved"]
        assert f2["retests"][0]["evidence_ids"]
    finally:
        target_server["fixed_flag"].unlink(missing_ok=True)


def test_tls_configuration_check(client, make_assessment, deps, executor, target_server, orchestrator):
    from tests.conftest import scope_body
    tls = target_server["tls"]
    body = scope_body(ports=(tls,), tools=("tls.configuration",))
    body["scope"]["targets"][0]["schemes"] = ["https"]
    op = client.as_user("operator@acme.test")
    a = client.post("/api/v1/assessments", json=body, headers=op).json()
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 202
    st = wait_status(client, op, a["id"], {"COMPLETED", "FAILED"}, 60)
    assert st["status"] == "COMPLETED", st
    f = _findings(client, op, a["id"])
    assert {"TLS-UNTRUSTED", "TLS-HOSTNAME", "TLS-EXPIRING", "TLS-LEGACY"} <= set(f), set(f)
    assert all(x["verification_status"] == "confirmed" for x in f.values())
    ev = client.get(f"/api/v1/evidence/{f['TLS-LEGACY']['evidence_ids'][0]}", headers=op).json()
    assert ev["content"]["tls"]["probe"] == "legacy-only" and ev["content"]["tls"]["version"] in ("TLS 1.0", "TLS 1.1")


def test_executor_grpc_status_over_mtls(client, deps, executor):
    from asvas import execgrpc
    st = client.get("/api/v1/system/status", headers=client.as_user("viewer@acme.test")).json()
    [w] = st["workers"]
    assert w["grpc"]["reachable"] is True and w["grpc"]["mtls"] is True, w
    # Without the control-plane client certificate the executor refuses the connection.
    from asvas.config import get_settings
    s = get_settings()
    real = s.executor_tls_cert
    s.executor_tls_cert = s.executor_tls_ca  # a certificate the executor will not accept as a client identity
    try:
        assert execgrpc.probe(w["grpc_addr"])["reachable"] is False
    finally:
        s.executor_tls_cert = real


def test_cancellation_delivered_over_grpc_only(client, make_assessment, deps, executor, target_server, orchestrator):
    """The Redis control stream is bypassed: only the mTLS gRPC Control RPC can stop the running sandbox."""
    from asvas import execgrpc
    from asvas.orchestration import bus
    weak = target_server["weak"]
    deps.provider_factory = Scripted(weak, ["/slow"])
    aid, op = _start(client, make_assessment, ports=(weak,), job_timeout_seconds=30)
    wait_status(client, op, aid, {"RUNNING"}, 30)
    time.sleep(1.0)
    data, sig = bus.signed_control({"type": "cancel_assessment", "tenant_id": str(tid_of()), "assessment_id": aid,
                                    "reason": "grpc-only test"})
    t0 = time.time()
    res = execgrpc.broadcast_control(deps.r, data, sig)
    assert res and res[0]["ok"] and res[0]["jobs_signalled"] == 1, res
    end = time.time() + 15
    while time.time() < end and jobs_of(aid)[0]["status"] == "RUNNING":
        time.sleep(0.2)
    job = jobs_of(aid)[0]
    assert job["status"] == "CANCELLED" and "grpc-only test" in (job["error"] or "") and time.time() - t0 < 10
    # A forged control message is refused by the executor even over the authenticated channel.
    bad = execgrpc.broadcast_control(deps.r, data, "0" * 64)
    assert bad and bad[0]["ok"] is False and bad[0]["detail"] == "INVALID_ARGUMENT"
