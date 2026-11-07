"""Encryption at rest (CP-11): envelope encryption, record binding, rotation, append-only evidence."""

import json
import os

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from asvas import crypto, keymgmt
from asvas.db import rows, tenant_tx
from asvas.orchestration import engine
from tests.test_lifecycle import jobs_of, result, start, tid_of


def test_seal_open_binding_and_tamper(tmp_path):
    kr = crypto.KeyRing.load(tmp_path / "k.json", create=True)
    s = kr.seal(b"secret evidence", "asvas:evidence:t:j:1:0")
    assert b"secret" not in s.ciphertext and len(s.dek_wrapped) == 12 + 32 + 16
    assert kr.open(s.ciphertext, s.dek_wrapped, s.kek_id, "asvas:evidence:t:j:1:0") == b"secret evidence"
    with pytest.raises(InvalidTag):  # ciphertext moved to another record/tenant
        kr.open(s.ciphertext, s.dek_wrapped, s.kek_id, "asvas:evidence:OTHER:j:1:0")
    bad = bytearray(s.ciphertext)
    bad[-1] ^= 1
    with pytest.raises(InvalidTag):
        kr.open(bytes(bad), s.dek_wrapped, s.kek_id, "asvas:evidence:t:j:1:0")


def test_rotation_keeps_old_data_readable(tmp_path):
    kr = crypto.KeyRing.load(tmp_path / "k.json", create=True)
    old = kr.seal(b"x", "a")
    new_id = kr.rotate()
    assert kr.active == new_id and old.kek_id != new_id
    reloaded = crypto.KeyRing.load(tmp_path / "k.json")
    assert reloaded.open(old.ciphertext, old.dek_wrapped, old.kek_id, "a") == b"x"
    w, kid = reloaded.rewrap(old.dek_wrapped, old.kek_id, "a")
    assert kid == new_id and reloaded.open(old.ciphertext, w, kid, "a") == b"x"


def test_keyring_permissions_enforced(tmp_path):
    p = tmp_path / "k.json"
    crypto.KeyRing.load(p, create=True)
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    os.chmod(p, 0o644)
    with pytest.raises(crypto.KeyRingError, match="must not be readable"):
        crypto.KeyRing.load(p)


def test_evidence_encrypted_in_database(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    engine.ingest_result(deps, result(job))
    with tenant_tx(tid_of()) as conn:
        stored = rows(conn, "SELECT id, content, enc_alg, kek_id FROM evidence")
    assert stored and all(r["enc_alg"] == crypto.ALG for r in stored)
    assert all(b"Set-Cookie" not in bytes(r["content"]) and b"Apache" not in bytes(r["content"]) for r in stored)
    ev = client.get(f"/api/v1/evidence/{stored[0]['id']}", headers=op).json()
    assert ev["integrity_ok"] and ev["content"]["response"]["status"] == 200
    assert ev["encryption"]["alg"] == crypto.ALG and "dek_wrapped" not in ev


def test_rotate_rewrap_and_append_only(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    engine.ingest_result(deps, result(job))
    before = keymgmt.status()
    keymgmt.rotate()
    res = keymgmt.rewrap()
    after = keymgmt.status()
    assert res["rewrapped"] == sum(before["by_kek"].values())
    assert list(after["by_kek"]) == [after["active_kek"]]
    with tenant_tx(tid_of()) as conn:
        [ev] = rows(conn, "SELECT id FROM evidence LIMIT 1")
    assert client.get(f"/api/v1/evidence/{ev['id']}", headers=op).json()["integrity_ok"]
    from sqlalchemy import create_engine
    owner = create_engine(os.environ["ASVAS_MIGRATION_DATABASE_URL"])
    for sql in ("UPDATE evidence SET content = 'x'::bytea", "UPDATE evidence SET sha256 = repeat('0', 64)",
                "DELETE FROM evidence"):
        # The application role lacks the privilege (only key re-wrapping columns are grantable) ...
        with pytest.raises(DBAPIError, match="permission denied"):
            with tenant_tx(tid_of()) as conn:
                conn.execute(text(sql))
        # ... and even the table owner is stopped by the append-only trigger.
        with pytest.raises(DBAPIError, match="append-only"):
            with tenant_tx(tid_of(), owner) as conn:
                conn.execute(text(sql))
    owner.dispose()
    with tenant_tx(tid_of()) as conn:
        audit = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'keys.rewrapped'")
    assert audit and json.dumps(audit[0]["data"])
