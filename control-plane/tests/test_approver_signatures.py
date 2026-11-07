"""PO-04: approval decisions require the approver's own Ed25519 signature over the exact decision."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from asvas.db import row, rows, tenant_tx
from asvas.signatures import decision_message
from tests.test_lifecycle import approval_setup, jobs_of, read_job_envelopes, tid_of


def _post(client, ap, body, headers):
    return client.post(f"/api/v1/approvals/{ap['id']}/decision", json=body, headers=headers)


def _register(client, headers):
    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    r = client.post("/api/v1/approver-keys", json={"public_key": pub}, headers=headers)
    assert r.status_code == 201, r.text
    return sk, r.json()["id"]


def _sig(sk, ap, decision="approve", binding=None, expires=None):
    msg = decision_message(ap["id"], decision, binding or ap["binding_hash"], expires or ap["expires_unix"])
    return base64.b64encode(sk.sign(msg.encode())).decode()


def test_signed_approval_is_recorded_and_dispatched(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    body = client.signed(apr, ap)
    assert _post(client, ap, body, apr).status_code == 200
    assert len(read_job_envelopes(deps.r)) == 1
    with tenant_tx(tid_of()) as conn:
        stored = row(conn, "SELECT signer_key_id, signature, signed_message FROM approvals WHERE id = :id", id=ap["id"])
        ev = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'approval.approved'")[0]["data"]
    assert str(stored["signer_key_id"]) == body["key_id"]
    assert stored["signed_message"] == decision_message(ap["id"], "approve", ap["binding_hash"], ap["expires_unix"])
    assert base64.b64encode(bytes(stored["signature"])).decode() == body["signature"]
    assert ev["signature"]["key_id"] == body["key_id"] and ev["signature"]["alg"] == "Ed25519"


def test_unsigned_decision_refused_and_audited(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    r = _post(client, ap, {"decision": "approve", "binding_hash": ap["binding_hash"]}, apr)
    assert r.status_code == 403 and "signature" in r.json()["title"]
    assert read_job_envelopes(deps.r) == [] and jobs_of(aid)[0]["status"] == "AWAITING_APPROVAL"
    with tenant_tx(tid_of()) as conn:
        assert row(conn, "SELECT status FROM approvals WHERE id = :id", id=ap["id"])["status"] == "PENDING"
        assert rows(conn, "SELECT 1 AS x FROM audit_events WHERE event_type = 'approval.signature_refused'")


def test_signature_cannot_be_reused_for_other_decision_or_binding(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    sk, kid = _register(client, apr)
    base = {"binding_hash": ap["binding_hash"], "key_id": kid}
    # a "reject" signature presented as "approve"
    assert _post(client, ap, {**base, "decision": "approve", "signature": _sig(sk, ap, "reject")}, apr).status_code == 403
    # signature over a different binding hash / expiry
    assert _post(client, ap, {**base, "decision": "approve", "signature": _sig(sk, ap, binding="a" * 64)},
                 apr).status_code == 403
    assert _post(client, ap, {**base, "decision": "approve", "signature": _sig(sk, ap, expires=1)}, apr).status_code == 403
    # garbage
    assert _post(client, ap, {**base, "decision": "approve", "signature": "AAAA"}, apr).status_code == 403
    assert _post(client, ap, {**base, "decision": "approve", "signature": _sig(sk, ap)}, apr).status_code == 200


def test_key_of_another_user_is_refused(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    adm, apr = client.as_user("admin@acme.test"), client.as_user("approver@acme.test")
    sk, admin_kid = _register(client, adm)
    r = _post(client, ap, {"decision": "approve", "binding_hash": ap["binding_hash"], "key_id": admin_kid,
                           "signature": _sig(sk, ap)}, apr)
    assert r.status_code == 403 and "not registered to the deciding user" in r.json()["title"]


def test_revoked_key_is_refused(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    sk, kid = _register(client, apr)
    assert client.post(f"/api/v1/approver-keys/{kid}/revoke", headers=apr).status_code == 200
    r = _post(client, ap, {"decision": "approve", "binding_hash": ap["binding_hash"], "key_id": kid,
                           "signature": _sig(sk, ap)}, apr)
    assert r.status_code == 403 and "revoked" in r.json()["title"]
    listed = client.get("/api/v1/approver-keys", headers=apr).json()
    assert listed[0]["revoked_at"] is not None


def test_signed_rejection(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    assert _post(client, ap, client.signed(apr, ap, "reject", reason="not now"), apr).status_code == 200
    assert jobs_of(aid)[0]["status"] == "DENIED"


def test_key_registration_validation(client):
    apr = client.as_user("approver@acme.test")
    assert client.post("/api/v1/approver-keys", json={"public_key": "AAAA"}, headers=apr).status_code == 422
    sk = Ed25519PrivateKey.generate()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    assert client.post("/api/v1/approver-keys", json={"public_key": pub}, headers=apr).status_code == 201
    assert client.post("/api/v1/approver-keys", json={"public_key": pub}, headers=apr).status_code == 409
    op = client.as_user("operator@acme.test")
    assert client.post("/api/v1/approver-keys", json={"public_key": pub}, headers=op).status_code == 403
