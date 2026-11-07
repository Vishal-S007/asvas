"""Per-approver decision signatures (requirement PO-04; spec pp. 4, 32).

The approver's client holds an Ed25519 private key (in the dashboard: a non-extractable WebCrypto key in
IndexedDB) and registers only the public key. Each decision is signed over a canonical message that binds the
approval id, the decision, the binding hash of the exact action and the approval expiry, so a signature cannot
be replayed for another approval, another action, the opposite decision or after the parameters change.

This is software-key signing, not WebAuthn: the key is protected by the browser profile, not by a hardware
authenticator, and there is no attestation. WebAuthn remains the target (see docs/requirements.md).
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "asvas-approval-v1"


def decision_message(approval_id, decision: str, binding_hash: str, expires_unix: int) -> str:
    return f"{PREFIX}|{approval_id}|{decision}|{binding_hash}|{expires_unix}"


def parse_public_key(b64: str) -> bytes:
    raw = base64.b64decode(b64, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    Ed25519PublicKey.from_public_bytes(raw)
    return raw


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify(public_key: bytes, signature_b64: str, message: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, message.encode())
        return True
    except (InvalidSignature, ValueError):
        return False
