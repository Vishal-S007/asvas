"""UI-04: read-only auditor role and live compliance control status; UI-03 advanced policy view."""

from __future__ import annotations

from tests.conftest import scope_body


def test_auditor_reads_controls_but_cannot_mutate(client):
    aud = client.as_user("auditor@acme.test")
    r = client.get("/api/v1/compliance/controls", headers=aud)
    assert r.status_code == 200
    ids = {c["id"]: c for c in r.json()["controls"]}
    assert {"audit-chain", "audit-export", "approval-signatures", "encryption-at-rest", "transport-tls",
            "policy-engine", "retention", "isolation"} <= set(ids)
    assert ids["audit-chain"]["status"] == "pass"
    assert ids["audit-export"]["status"] == "attention"  # nothing exported in a fresh test DB
    assert ids["isolation"]["status"] == "attention"  # Firecracker is not claimed
    assert all(c["status"] in ("pass", "attention", "info") for c in ids.values())
    # read access to ordinary views
    assert client.get("/api/v1/audit", headers=aud).status_code == 200
    assert client.get("/api/v1/assessments", headers=aud).status_code == 200
    # every mutation is refused
    assert client.post("/api/v1/assessments", json=scope_body(), headers=aud).status_code == 403
    assert client.post("/api/v1/system/emergency-stop", json={"reason": "x"}, headers=aud).status_code == 403
    assert client.post("/api/v1/approver-keys", json={"public_key": "A" * 44}, headers=aud).status_code == 403
    assert client.get("/api/v1/system/policy", headers=aud).status_code == 403


def test_controls_restricted_to_auditor_and_admin(client):
    for who, code in (("viewer@acme.test", 403), ("operator@acme.test", 403), ("approver@acme.test", 403),
                      ("admin@acme.test", 200)):
        assert client.get("/api/v1/compliance/controls", headers=client.as_user(who)).status_code == code


def test_controls_reflect_live_state(client, make_assessment, deps, tmp_path):
    from asvas import audit_export
    make_assessment()  # produces audit events for the tenant
    audit_export.export(tmp_path, audit_export.load_signing_key())
    aud = client.as_user("auditor@acme.test")
    c = {x["id"]: x for x in client.get("/api/v1/compliance/controls", headers=aud).json()["controls"]}
    assert c["audit-export"]["status"] == "pass" and c["audit-export"]["data"]["last_checkpoint"]["seq"] == 1
    assert c["policy-engine"]["data"]["files_sha256"]


def test_policy_source_is_read_only_view(client):
    op = client.as_user("operator@acme.test")
    files = client.get("/api/v1/system/policy", headers=op).json()["files"]
    assert any(f["path"].endswith("decision.rego") and "package" in f["source"] for f in files)
    assert client.put("/api/v1/system/policy", json={}, headers=client.as_user("admin@acme.test")).status_code == 405
