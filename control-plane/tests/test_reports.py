"""PDF rendering by the separate report worker (DA-11)."""

import hashlib
import json

from asvas import report_worker
from asvas.orchestration import engine
from tests.test_lifecycle import jobs_of, result, start


def test_pdf_report_rendered_by_worker(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    engine.ingest_result(deps, result(job))
    r = client.post(f"/api/v1/assessments/{aid}/reports", headers=op)
    assert r.status_code == 202
    rid = r.json()["report_id"]
    assert client.get(f"/api/v1/reports/{rid}/download", headers=op).status_code == 409  # not rendered yet
    [(_, msgs)] = deps.r.xread({"asvas:reports": "0-0"})
    msg = json.loads(msgs[0][1]["message"])
    assert report_worker.handle(None, msg) == "ready"
    assert report_worker.handle(None, msg) == "ignored"  # duplicate delivery is idempotent
    meta = client.get(f"/api/v1/reports/{rid}", headers=op).json()
    assert meta["status"] == "READY"
    d = client.get(f"/api/v1/reports/{rid}/download", headers=op)
    assert d.status_code == 200 and d.content.startswith(b"%PDF")
    assert hashlib.sha256(d.content).hexdigest() == meta["sha256"] == d.headers["x-content-sha256"]
    assert client.get(f"/api/v1/reports/{rid}", headers=client.as_user("operator@globex.test")).status_code == 404


def test_untrusted_text_is_escaped_in_pdf():
    rep = {"generated_at": "now", "audit_chain": {"ok": True, "events": 1}, "limitations": ["x"],
           "assessment": {"id": "a", "name": "<b>bad</b> & <font size=99>", "status": "COMPLETED", "started_at": None,
                          "finished_at": None, "authorization": {"reference": "r", "authorized_by": "b"},
                          "planner": {"provider": "p", "is_live_ai": False, "note": None}},
           "findings": [{"severity": "low", "title": "<para>x</para>", "asset": "a", "check_id": "c", "rule_id": "r",
                         "cwe": None, "verification_status": "suspected", "confidence": "low", "state": "open",
                         "observed_behavior": "Server: <script>alert(1)</script>", "severity_rationale": "s",
                         "cvss": None, "remediation": "r", "evidence": [], "retest_history": []}]}
    assert report_worker.render_pdf(rep).startswith(b"%PDF")
