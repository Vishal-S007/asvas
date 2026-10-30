"""Authentication, authorization, tenant isolation, API validation, immutability."""

import uuid

import jwt
from sqlalchemy import text

from asvas.db import get_engine, tenant_tx
from tests.conftest import scope_body


def test_unauthenticated_and_bad_tokens(client):
    assert client.get("/api/v1/assessments").status_code == 401
    assert client.get("/api/v1/assessments", headers={"Authorization": "Bearer nope"}).status_code == 401
    forged = jwt.encode({"sub": str(uuid.uuid4()), "tid": str(uuid.uuid4()), "role": "admin", "exp": 9999999999,
                         "iss": "asvas", "aud": "asvas-api"}, "wrong-secret", algorithm="HS256")
    r = client.get("/api/v1/assessments", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401 and r.headers["content-type"] == "application/problem+json"


def test_role_claim_in_token_cannot_escalate(client):
    """The role is re-read from the DB; a token claiming admin for a viewer does not grant admin."""
    from asvas.auth import lookup_user
    from asvas.config import get_settings
    u = lookup_user(email="viewer@acme.test")
    tok = jwt.encode({"sub": str(u["id"]), "tid": str(u["tenant_id"]), "role": "admin", "exp": 9999999999,
                      "iss": "asvas", "aud": "asvas-api"}, get_settings().jwt_secret.get_secret_value(), algorithm="HS256")
    r = client.post("/api/v1/system/emergency-stop", json={"reason": "test"}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_role_boundaries(client, make_assessment):
    v = client.as_user("viewer@acme.test")
    assert client.post("/api/v1/assessments", json=scope_body(), headers=v).status_code == 403
    a = make_assessment()
    op = client.as_user("operator@acme.test")
    assert client.post(f"/api/v1/approvals/{uuid.uuid4()}/decision",
                       json={"decision": "approve", "binding_hash": "0" * 64}, headers=op).status_code == 403
    assert client.post("/api/v1/system/emergency-stop", json={"reason": "x y z"}, headers=op).status_code == 403
    assert client.get(f"/api/v1/assessments/{a['id']}", headers=v).status_code == 200


def test_tenant_isolation_api_and_rls(client, make_assessment):
    a = make_assessment()
    g = client.as_user("operator@globex.test")
    assert client.get(f"/api/v1/assessments/{a['id']}", headers=g).status_code == 404
    assert client.get("/api/v1/assessments", headers=g).json() == []
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=g).status_code == 404
    # Directly at the database: the app role with globex tenant set cannot see or modify acme rows.
    from asvas.auth import lookup_user
    gid = lookup_user(email="operator@globex.test")["tenant_id"]
    with tenant_tx(gid) as conn:
        assert conn.execute(text("SELECT count(*) FROM assessments")).scalar() == 0
        assert conn.execute(text("UPDATE assessments SET name='pwned' WHERE id=:id"), {"id": a["id"]}).rowcount == 0
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 0
    # With no tenant bound, nothing is visible at all.
    with get_engine().begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM assessments")).scalar() == 0


def test_rls_blocks_cross_tenant_insert(client, make_assessment):
    import pytest
    from sqlalchemy.exc import ProgrammingError

    from asvas.auth import lookup_user
    acme = lookup_user(email="operator@acme.test")
    gid = lookup_user(email="operator@globex.test")["tenant_id"]
    with pytest.raises(ProgrammingError, match="row-level security"):
        with tenant_tx(gid) as conn:
            conn.execute(text("INSERT INTO audit_events (tenant_id, actor, event_type, prev_hash, hash) "
                              "VALUES (:t,'x','x',:h,:h)"), {"t": str(acme["tenant_id"]), "h": "0" * 64})


def test_validation_problem_details(client):
    op = client.as_user("operator@acme.test")
    body = scope_body()
    body["scope"]["targets"][0]["host"] = "http://evil"
    body["unexpected"] = 1
    r = client.post("/api/v1/assessments", json=body, headers=op)
    assert r.status_code == 422 and r.headers["content-type"] == "application/problem+json"
    locs = [e["loc"] for e in r.json()["detail"]]
    assert ["body", "unexpected"] in locs


def test_scope_immutable_after_start_and_window_enforced(client, make_assessment):
    op = client.as_user("operator@acme.test")
    expired = make_assessment(valid_minutes=(-120, -60))
    r = client.post(f"/api/v1/assessments/{expired['id']}/start", headers=op)
    assert r.status_code == 422 and "expired" in r.json()["title"]
    a = make_assessment()
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 202
    r = client.patch(f"/api/v1/assessments/{a['id']}", json={"name": "renamed"}, headers=op)
    assert r.status_code == 409
    assert client.post(f"/api/v1/assessments/{a['id']}/start", headers=op).status_code == 409


def test_rate_limit(client, monkeypatch):
    from asvas.config import get_settings
    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 3)
    v = client.as_user("viewer@acme.test")
    codes = [client.get("/api/v1/me", headers=v).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_audit_append_only_and_chain(client, make_assessment):
    import pytest
    from sqlalchemy.exc import DBAPIError

    from asvas.audit import verify_chain
    from asvas.auth import lookup_user
    make_assessment()
    tid = lookup_user(email="operator@acme.test")["tenant_id"]
    with tenant_tx(tid) as conn:
        assert verify_chain(conn, tid)["ok"]
    for sql in ("UPDATE audit_events SET actor='x'", "DELETE FROM audit_events"):
        with pytest.raises(DBAPIError):
            with tenant_tx(tid) as conn:
                conn.execute(text(sql))
    r = client.get("/api/v1/audit/verify", headers=client.as_user("viewer@acme.test"))
    assert r.json()["ok"] is True
