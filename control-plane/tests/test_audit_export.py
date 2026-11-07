"""DA-10: write-once audit export with Ed25519-signed checkpoints, offline verification and DB cross-check."""

from __future__ import annotations

import json
import os
import shutil
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text

from asvas import audit, audit_export
from asvas.db import tenant_tx
from tests.test_lifecycle import tid_of


@pytest.fixture()
def ledger(clean):
    k = audit_export.load_signing_key()
    return k, audit_export.public_key_b64(k)


def _add(n=3):
    with tenant_tx(tid_of()) as conn:
        for i in range(n):
            audit.record(conn, tid_of(), "system:test", "test.event", {"i": i, "f": 1.5})


def _tenant_dir(out):
    return out / str(tid_of())


def test_export_verify_and_incremental_chain(ledger, tmp_path):
    k, pub = ledger
    _add()
    first = audit_export.export(tmp_path, k)
    assert any(m["seq"] == 1 for m in first)
    _add(2)
    second = audit_export.export(tmp_path, k)
    mine = [m for m in second if m["tenant_id"] == str(tid_of())]
    assert mine and mine[0]["seq"] == 2  # continues the chain; includes the 'audit.exported' event of run 1
    v = audit_export.verify(tmp_path, pub)
    assert v["ok"], v
    t = v["tenants"][str(tid_of())]
    assert t["checkpoints"] == 2
    seg = _tenant_dir(tmp_path) / "00000001.events.jsonl"
    assert stat.S_IMODE(seg.stat().st_mode) == 0o444
    assert audit_export.cross_check(tmp_path, pub)["ok"]


def test_files_are_never_overwritten(ledger, tmp_path):
    k, _ = ledger
    _add()
    audit_export.export(tmp_path, k)
    with pytest.raises(FileExistsError):
        audit_export._write_once(_tenant_dir(tmp_path) / "00000001.events.jsonl", b"x")


def test_tampered_segment_detected(ledger, tmp_path):
    k, pub = ledger
    _add()
    audit_export.export(tmp_path, k)
    seg = _tenant_dir(tmp_path) / "00000001.events.jsonl"
    os.chmod(seg, 0o644)
    lines = seg.read_bytes().splitlines()
    ev = json.loads(lines[0])
    ev["actor"] = "user:attacker"
    seg.write_bytes(b"\n".join([json.dumps(ev).encode(), *lines[1:]]) + b"\n")
    v = audit_export.verify(tmp_path, pub)
    assert not v["ok"] and "segment digest" in v["tenants"][str(tid_of())]["error"]


def test_forged_checkpoint_with_recomputed_digest_detected(ledger, tmp_path):
    """An attacker who rewrites a segment and fixes the digest still cannot re-sign the checkpoint."""
    k, pub = ledger
    _add()
    audit_export.export(tmp_path, k)
    cpf = _tenant_dir(tmp_path) / "00000001.checkpoint.json"
    os.chmod(cpf, 0o644)
    doc = json.loads(cpf.read_text())
    doc["checkpoint"]["segment_sha256"] = "0" * 64
    cpf.write_text(json.dumps(doc))
    v = audit_export.verify(tmp_path, pub)
    assert not v["ok"] and "signature" in v["tenants"][str(tid_of())]["error"]


def test_deleted_checkpoint_detected(ledger, tmp_path):
    k, pub = ledger
    _add()
    audit_export.export(tmp_path, k)
    _add()
    audit_export.export(tmp_path, k)
    os.remove(_tenant_dir(tmp_path) / "00000001.checkpoint.json")
    assert not audit_export.verify(tmp_path, pub)["ok"]


def test_wrong_public_key_rejected(ledger, tmp_path):
    k, _ = ledger
    _add()
    audit_export.export(tmp_path, k)
    other = audit_export.public_key_b64(Ed25519PrivateKey.generate())
    assert not audit_export.verify(tmp_path, other)["ok"]


def test_cross_check_detects_superuser_tampering(ledger, tmp_path):
    """Even with the append-only trigger disabled by a DB owner, the earlier export exposes the change."""
    k, pub = ledger
    _add()
    audit_export.export(tmp_path, k)
    eng = create_engine(os.environ["ASVAS_MIGRATION_DATABASE_URL"])
    with eng.begin() as c:
        c.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tid_of())})
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        victim = c.execute(text("SELECT id FROM audit_events WHERE event_type = 'test.event' ORDER BY id LIMIT 1")).scalar()
        c.execute(text("DELETE FROM audit_events WHERE id = :i"), {"i": victim})
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))
    eng.dispose()
    res = audit_export.cross_check(tmp_path, pub)
    t = res["tenants"][str(tid_of())]
    assert not res["ok"] and victim in t["missing"]


def test_checkpoint_rows_are_append_only(ledger, tmp_path):
    k, _ = ledger
    _add()
    audit_export.export(tmp_path, k)
    eng = create_engine(os.environ["ASVAS_MIGRATION_DATABASE_URL"])
    with pytest.raises(Exception, match="append-only"), eng.begin() as c:
        c.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tid_of())})
        c.execute(text("UPDATE audit_checkpoints SET last_hash = repeat('0', 64)"))
    eng.dispose()


def test_signing_key_permissions_enforced(tmp_path):
    p = tmp_path / "k.pem"
    audit_export.load_signing_key(p, create=True)
    os.chmod(p, 0o644)
    with pytest.raises(audit_export.ExportError, match="group/others"):
        audit_export.load_signing_key(p)
    shutil.rmtree(tmp_path, ignore_errors=True)
