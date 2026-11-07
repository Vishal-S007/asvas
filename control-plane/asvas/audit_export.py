"""Write-once audit export with signed checkpoints (requirement DA-10; spec pp. 6, 14, 42, 58, 63).

`export()` appends, per tenant, the audit events written since the previous checkpoint to a new segment file
(JSON lines) and writes a checkpoint naming the event range, the last chain hash, the segment's SHA-256 and the
SHA-256 of the previous checkpoint. The checkpoint is signed with an Ed25519 ledger key that the database never
sees. Files are created exclusively (never overwritten) and made read-only.

`verify()` needs only the export directory and the ledger public key: it checks every signature, the checkpoint
chain, each segment digest and every event hash, so tampering with the database (even by a superuser who
disables the append-only trigger) is detectable by comparing against an earlier export (`cross_check`).

Limits, stated plainly: a local directory is not WORM storage — anyone with write access to it can delete files
(deletion is detected by `verify` as a gap, not prevented). Production should point the export at storage with
an object lock / retention policy (e.g. S3 Object Lock in compliance mode); that adapter is not implemented.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text

from asvas import audit
from asvas.canonical import canonical_json
from asvas.config import get_settings
from asvas.db import list_tenant_ids, row, rows, tenant_tx

VERSION = 1


class ExportError(RuntimeError):
    pass


# --------------------------------------------------------------------------- ledger signing key
def load_signing_key(path: str | Path | None = None, create: bool | None = None) -> Ed25519PrivateKey:
    s = get_settings()
    p = Path(path or s.audit_signing_key_file)
    if not p.exists():
        if not (s.env != "production" if create is None else create):
            raise ExportError(f"audit signing key {p} does not exist")
        p.parent.mkdir(parents=True, exist_ok=True)
        pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    if stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise ExportError(f"audit signing key {p} must not be readable by group/others")
    k = serialization.load_pem_private_key(p.read_bytes(), password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise ExportError("audit signing key must be Ed25519")
    return k


def public_key_b64(k: Ed25519PrivateKey) -> str:
    return base64.b64encode(k.public_key().public_bytes_raw()).decode()


def _fp(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()


# --------------------------------------------------------------------------- export
def _write_once(p: Path, data: bytes) -> None:
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)  # fails if the file already exists
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def export(out_dir: str | Path, key: Ed25519PrivateKey | None = None, max_events: int = 10_000) -> list[dict]:
    key = key or load_signing_key()
    pub = key.public_key().public_bytes_raw()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    made = []
    for tenant in list_tenant_ids():
        with tenant_tx(tenant) as conn:
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtext('asvas_audit_export:' || :t))"), {"t": str(tenant)})
            last = row(conn, "SELECT * FROM audit_checkpoints ORDER BY seq DESC LIMIT 1")
            after = last["to_id"] if last else 0
            evs = [audit.event_record(r) for r in rows(
                conn, "SELECT * FROM audit_events WHERE id > :a ORDER BY id LIMIT :n", a=after, n=max_events)]
            if not evs:
                continue
            seq = (last["seq"] + 1) if last else 1
            tdir = out / str(tenant)
            tdir.mkdir(exist_ok=True)
            seg_name = f"{seq:08d}.events.jsonl"
            seg = b"".join(json.dumps(e, sort_keys=True, separators=(",", ":")).encode() + b"\n" for e in evs)
            cp = {"v": VERSION, "tenant_id": str(tenant), "seq": seq, "from_id": evs[0]["id"], "to_id": evs[-1]["id"],
                  "count": len(evs), "first_prev_hash": evs[0]["prev_hash"], "last_hash": evs[-1]["hash"],
                  "segment": seg_name, "segment_sha256": hashlib.sha256(seg).hexdigest(),
                  "prev_checkpoint_sha256": last["checkpoint_sha256"] if last else None,
                  "created_at": dt.datetime.now(dt.UTC).isoformat(), "key_fingerprint": _fp(pub)}
            cp_bytes = canonical_json(cp).encode()
            cp_sha = hashlib.sha256(cp_bytes).hexdigest()
            sig = key.sign(cp_bytes)
            _write_once(tdir / seg_name, seg)
            _write_once(tdir / f"{seq:08d}.checkpoint.json",
                        json.dumps({"checkpoint": cp, "signature": base64.b64encode(sig).decode()}, indent=1).encode())
            conn.execute(text(
                "INSERT INTO audit_checkpoints (tenant_id, seq, from_id, to_id, event_count, last_hash, segment_name, "
                "segment_sha256, checkpoint_sha256, signature, key_fingerprint) VALUES "
                "(:t,:seq,:f,:to,:n,:lh,:sn,:ss,:cs,:sig,:kf)"),
                {"t": str(tenant), "seq": seq, "f": cp["from_id"], "to": cp["to_id"], "n": cp["count"],
                 "lh": cp["last_hash"], "sn": seg_name, "ss": cp["segment_sha256"], "cs": cp_sha, "sig": sig,
                 "kf": cp["key_fingerprint"]})
            audit.record(conn, tenant, "system:audit-export", "audit.exported",
                         {"seq": seq, "from_id": cp["from_id"], "to_id": cp["to_id"], "count": cp["count"],
                          "checkpoint_sha256": cp_sha})
            made.append({"tenant_id": str(tenant), "seq": seq, "count": cp["count"], "checkpoint_sha256": cp_sha})
    return made


# --------------------------------------------------------------------------- offline verification
def verify(export_dir: str | Path, public_key_b64_: str) -> dict[str, Any]:
    """Verify an export directory using only the ledger public key. No database access."""
    pub_raw = base64.b64decode(public_key_b64_)
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    results: dict[str, Any] = {"ok": True, "tenants": {}}
    for tdir in sorted(p for p in Path(export_dir).iterdir() if p.is_dir()):
        res = _verify_tenant(tdir, pub, _fp(pub_raw))
        results["tenants"][tdir.name] = res
        results["ok"] &= res["ok"]
    return results


def _verify_tenant(tdir: Path, pub: Ed25519PublicKey, fp: str) -> dict[str, Any]:
    def fail(why: str, **kw) -> dict[str, Any]:
        return {"ok": False, "error": why, **kw}

    files = sorted(tdir.glob("*.checkpoint.json"))
    prev_cp_sha, prev_hash, events, last_id = None, audit.GENESIS, 0, 0
    for i, f in enumerate(files, start=1):
        doc = json.loads(f.read_bytes())
        cp, cp_bytes = doc["checkpoint"], canonical_json(doc["checkpoint"]).encode()
        try:
            pub.verify(base64.b64decode(doc["signature"]), cp_bytes)
        except Exception:  # noqa: BLE001
            return fail("checkpoint signature invalid", seq=i)
        if cp["seq"] != i or f.name != f"{i:08d}.checkpoint.json":
            return fail("checkpoint sequence gap or reordering", seq=i)
        if cp["tenant_id"] != tdir.name or cp["key_fingerprint"] != fp:
            return fail("checkpoint names another tenant or key", seq=i)
        if cp["prev_checkpoint_sha256"] != prev_cp_sha:
            return fail("checkpoint chain broken", seq=i)
        seg_path = tdir / cp["segment"]
        if not seg_path.exists():
            return fail("segment missing", seq=i)
        seg = seg_path.read_bytes()
        if hashlib.sha256(seg).hexdigest() != cp["segment_sha256"]:
            return fail("segment digest mismatch (segment modified)", seq=i)
        lines = seg.splitlines()
        if len(lines) != cp["count"]:
            return fail("segment event count mismatch", seq=i)
        for line in lines:
            ev = json.loads(line)
            if ev["id"] <= last_id or ev["prev_hash"] != prev_hash or audit.event_hash(ev) != ev["hash"]:
                return fail("event hash chain broken", seq=i, event_id=ev["id"])
            prev_hash, last_id = ev["hash"], ev["id"]
            events += 1
        if cp["from_id"] != json.loads(lines[0])["id"] or cp["to_id"] != last_id or cp["last_hash"] != prev_hash:
            return fail("checkpoint does not match its segment", seq=i)
        prev_cp_sha = hashlib.sha256(cp_bytes).hexdigest()
    return {"ok": True, "checkpoints": len(files), "events": events, "last_hash": prev_hash,
            "last_checkpoint_sha256": prev_cp_sha}


def cross_check(export_dir: str | Path, public_key_b64_: str) -> dict[str, Any]:
    """Compare the live database against a verified export: every exported event must still be present, unchanged."""
    v = verify(export_dir, public_key_b64_)
    if not v["ok"]:
        return {"ok": False, "error": "export does not verify", "verify": v}
    out: dict[str, Any] = {"ok": True, "tenants": {}}
    for tdir in sorted(p for p in Path(export_dir).iterdir() if p.is_dir()):
        exported = {}
        for seg in sorted(tdir.glob("*.events.jsonl")):
            for line in seg.read_bytes().splitlines():
                ev = json.loads(line)
                exported[ev["id"]] = ev["hash"]
        with tenant_tx(tdir.name) as conn:
            live = {r["id"]: r["hash"] for r in rows(conn, "SELECT id, hash FROM audit_events WHERE id <= :m",
                                                    m=max(exported, default=0))}
            chain = audit.verify_chain(conn, tdir.name)
        missing = sorted(set(exported) - set(live))
        changed = sorted(i for i in exported if i in live and live[i] != exported[i])
        res = {"ok": not missing and not changed and chain["ok"], "missing": missing[:20], "changed": changed[:20],
               "db_chain": chain}
        out["tenants"][tdir.name] = res
        out["ok"] &= res["ok"]
    return out


