"""Envelope encryption at rest (requirement CP-11; spec pp. 7, 15, 24, 85).

Each object gets a fresh 256-bit data key (DEK). Content is sealed with AES-256-GCM under the DEK; the DEK is
wrapped with AES-256-GCM under a key-encryption key (KEK) from the key ring. Both layers bind an associated-data
string naming the record (tenant, table, identifiers), so ciphertext cannot be moved to another row or tenant.

The key ring is a local file standing in for a KMS: {"active": "<kek id>", "keys": {"<kek id>": "<base64 32 bytes>"}}.
It must live outside the repository (default var/keys/, git-ignored) and be readable only by the service user.
Rotation adds a new active KEK; `asvas keys rewrap` re-wraps stored DEKs without touching the sealed content.
A real KMS (AWS KMS, Vault Transit) would implement the same wrap/unwrap interface.
"""

from __future__ import annotations

import base64
import functools
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asvas.config import get_settings

ALG = "AES-256-GCM+envelope-v1"


class KeyRingError(RuntimeError):
    pass


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes  # nonce(12) || AES-GCM(DEK, plaintext, aad)
    dek_wrapped: bytes  # nonce(12) || AES-GCM(KEK, DEK, aad|kek_id)
    kek_id: str
    alg: str = ALG


class KeyRing:
    def __init__(self, path: Path, data: dict):
        self.path = path
        self.active: str = data["active"]
        self.keys: dict[str, bytes] = {k: base64.b64decode(v) for k, v in data["keys"].items()}
        if self.active not in self.keys or any(len(k) != 32 for k in self.keys.values()):
            raise KeyRingError("key ring is malformed (active key missing or key not 256-bit)")

    @classmethod
    def load(cls, path: str | Path, create: bool = False) -> KeyRing:
        p = Path(path)
        if not p.exists():
            if not create:
                raise KeyRingError(f"key ring {p} does not exist")
            p.parent.mkdir(parents=True, exist_ok=True)
            kid = "k-" + secrets.token_hex(4)
            _write(p, {"active": kid, "keys": {kid: base64.b64encode(secrets.token_bytes(32)).decode()}})
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            raise KeyRingError(f"key ring {p} must not be readable by group/others (mode {oct(mode)})")
        return cls(p, json.loads(p.read_text()))

    def rotate(self) -> str:
        kid = "k-" + secrets.token_hex(4)
        self.keys[kid] = secrets.token_bytes(32)
        self.active = kid
        _write(self.path, {"active": kid, "keys": {k: base64.b64encode(v).decode() for k, v in self.keys.items()}})
        return kid

    # -- envelope operations
    def seal(self, plaintext: bytes, aad: str) -> Sealed:
        dek = AESGCM.generate_key(bit_length=256)
        n1, n2 = os.urandom(12), os.urandom(12)
        ct = n1 + AESGCM(dek).encrypt(n1, plaintext, aad.encode())
        wrapped = n2 + AESGCM(self.keys[self.active]).encrypt(n2, dek, _wrap_aad(aad, self.active))
        return Sealed(ct, wrapped, self.active)

    def unwrap(self, dek_wrapped: bytes, kek_id: str, aad: str) -> bytes:
        kek = self.keys.get(kek_id)
        if kek is None:
            raise KeyRingError(f"key {kek_id!r} is not in the key ring (retired too early?)")
        return AESGCM(kek).decrypt(dek_wrapped[:12], dek_wrapped[12:], _wrap_aad(aad, kek_id))

    def open(self, ciphertext: bytes, dek_wrapped: bytes, kek_id: str, aad: str) -> bytes:
        dek = self.unwrap(dek_wrapped, kek_id, aad)
        return AESGCM(dek).decrypt(ciphertext[:12], ciphertext[12:], aad.encode())

    def rewrap(self, dek_wrapped: bytes, kek_id: str, aad: str) -> tuple[bytes, str]:
        dek = self.unwrap(dek_wrapped, kek_id, aad)
        n = os.urandom(12)
        return n + AESGCM(self.keys[self.active]).encrypt(n, dek, _wrap_aad(aad, self.active)), self.active


def _wrap_aad(aad: str, kek_id: str) -> bytes:
    return f"{aad}|kek={kek_id}".encode()


def _write(p: Path, data: dict) -> None:
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, p)


@functools.lru_cache
def keyring() -> KeyRing:
    s = get_settings()
    return KeyRing.load(s.keyring_file, create=s.env != "production")


def evidence_aad(tenant_id, job_id, attempt: int, seq: int) -> str:
    return f"asvas:evidence:{tenant_id}:{job_id}:{attempt}:{seq}"


def report_aad(tenant_id, report_id) -> str:
    return f"asvas:report:{tenant_id}:{report_id}"
