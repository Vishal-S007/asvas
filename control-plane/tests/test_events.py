"""Live event stream (UI-01): SSE of audit events, tenant-scoped, ends when the assessment is terminal."""

import json

from asvas.orchestration import engine
from tests.test_lifecycle import jobs_of, result, start


def parse(text):
    out = []
    for block in text.split("\n\n"):
        f = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(":"))
        if "event" in f:
            out.append((f["event"], json.loads(f["data"]), f.get("id")))
    return out


def test_event_stream_replays_and_ends(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    engine.ingest_result(deps, *result(job))
    r = client.get(f"/api/v1/assessments/{aid}/events?max_seconds=20", headers=op)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    evs = parse(r.text)
    audit = [e for e in evs if e[0] == "audit"]
    types = [e[1]["event_type"] for e in audit]
    assert "assessment.transition" in types and "tool.dispatched" in types and "finding.created" in types
    ids = [int(e[2]) for e in audit]
    assert ids == sorted(ids)
    assert evs[-1][0] == "end" and evs[-1][1]["status"] == "COMPLETED"
    # Resume: Last-Event-ID skips what was already delivered.
    r2 = client.get(f"/api/v1/assessments/{aid}/events?max_seconds=20", headers={**op, "Last-Event-ID": str(ids[-1])})
    assert [e for e in parse(r2.text) if e[0] == "audit"] == []


def test_event_stream_tenant_scoped(client, make_assessment, deps):
    aid, _ = start(client, make_assessment, deps, ports=(18080,))
    assert client.get(f"/api/v1/assessments/{aid}/events?max_seconds=1",
                      headers=client.as_user("operator@globex.test")).status_code == 404
    assert client.get(f"/api/v1/assessments/{aid}/events?max_seconds=1").status_code == 401
