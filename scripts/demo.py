"""Local demo walkthrough against the running dev stack (see docs/demo.md). Uses only the bundled test target."""

import datetime as dt
import json
import sys
import time
import urllib.request

API = "http://127.0.0.1:8000/api/v1"


def call(method, path, token=None, body=None):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw and r.headers.get_content_type().endswith("json") else raw.decode()
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def login(email):
    return call("POST", "/auth/dev-login", body={"email": email})[1]["access_token"]


def wait(token, aid, statuses, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        a = call("GET", f"/assessments/{aid}", token)[1]
        if a["status"] in statuses:
            return a
        time.sleep(1)
    raise SystemExit(f"timeout waiting for {statuses}; last={a['status']}")


def main():
    op, ap = login("operator@acme.test"), login("approver@acme.test")
    now = dt.datetime.now(dt.UTC)
    body = {"name": "Local test target demo", "description": "Bundled deliberately-misconfigured target",
            "scope": {"targets": [{"host": "127.0.0.1", "ports": [18080, 18081], "schemes": ["http"]}],
                      "allowed_cidrs": ["127.0.0.1/32"], "excluded_cidrs": [],
                      "authorization": {"statement": "Local development target owned by the operator; non-destructive checks only.",
                                        "reference": "DEV-LOCAL-1", "authorized_by": "Ada Admin",
                                        "valid_from": (now - dt.timedelta(minutes=5)).isoformat(),
                                        "valid_until": (now + dt.timedelta(days=1)).isoformat()}},
            "testing_policy": {"allowed_tools": ["http.security_headers", "http.allowed_methods"],
                               "approval_required_risk_tiers": ["medium", "high"]}}
    st, a = call("POST", "/assessments", op, body)
    assert st == 201, a
    aid = a["id"]
    print("created", aid)
    print("start ->", call("POST", f"/assessments/{aid}/start", op))
    a = wait(op, aid, {"AWAITING_APPROVAL", "COMPLETED", "FAILED"})
    print("status:", a["status"], a["job_counts"])
    pending = [x for x in call("GET", "/approvals?status=PENDING", ap)[1] if x["assessment_id"] == aid]
    for x in pending:
        print("self-approval by operator ->", call("POST", f"/approvals/{x['id']}/decision", op,
                                                  {"decision": "approve", "binding_hash": x["binding_hash"]})[0])
        print("approve", x["binding_summary"]["target"], "->",
              call("POST", f"/approvals/{x['id']}/decision", ap, {"decision": "approve", "binding_hash": x["binding_hash"]})[1])
    a = wait(op, aid, {"COMPLETED", "FAILED"})
    print("final:", a["status"], a["job_counts"], "provider:", a["provider_name"], "live AI:", a["provider_is_live_ai"])
    for f in call("GET", f"/assessments/{aid}/findings", op)[1]:
        print(f"  [{f['severity']:<6}] {f['verification_status']:<9} {f['rule_id']:<18} {f['asset']}  ev={len(f['evidence_ids'])}")
    print(call("GET", "/audit/verify", op)[1])
    return aid


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
