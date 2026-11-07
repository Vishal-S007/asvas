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


def test_every_control_has_reference_mappings_and_disclaimer(client):
    import re

    from asvas.compliance_map import MAP
    aud = client.as_user("auditor@acme.test")
    d = client.get("/api/v1/compliance/controls", headers=aud).json()
    assert "not an assessment" in d["mapping_disclaimer"] and "certification" in d["mapping_disclaimer"]
    for c in d["controls"]:
        m = c["mappings"]
        assert c["id"] in MAP and m["nist_800_53"] and m["iso_27001"] and m["soc2"], c["id"]
        assert all(re.fullmatch(r"[A-Z]{2}-\d+(\(\d+\))?", x) for x in m["nist_800_53"])
        assert all(re.fullmatch(r"A\.[5-8]\.\d+", x) for x in m["iso_27001"])
        assert all(re.fullmatch(r"(CC\d\.\d|C1\.\d)", x) for x in m["soc2"])
        assert all(re.fullmatch(r"V\d+\.\d+", x) for x in m["owasp_asvs"])
    assert set(MAP) == {c["id"] for c in d["controls"]}  # no stale mapping entries


def test_csv_export_auditor_only_and_audited(client):
    from asvas.db import rows, tenant_tx
    from tests.test_lifecycle import tid_of
    r = client.get("/api/v1/compliance/controls.csv", headers=client.as_user("auditor@acme.test"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.splitlines()
    assert lines[0].startswith("# Reference mapping only") and lines[1].startswith("control,requirement,status")
    assert any(",AC-5," in x for x in lines) and any("A.8.24" in x for x in lines)
    assert client.get("/api/v1/compliance/controls.csv", headers=client.as_user("operator@acme.test")).status_code == 403
    with tenant_tx(tid_of()) as conn:
        assert rows(conn, "SELECT 1 AS x FROM audit_events WHERE event_type = 'compliance.exported'")
