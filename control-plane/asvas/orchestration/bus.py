"""Redis Streams event bus (spec pp. 23, 66-67, 81) and signed job envelopes."""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import time
from typing import Any

import redis

from asvas.canonical import canonical_json, hmac_hex
from asvas.config import get_settings
from asvas.orchestration import wire

JOBS = "asvas:jobs"
RESULTS = "asvas:results"
CONTROL = "asvas:control"
ORCH = "asvas:orchestrator"
WORKERS = "asvas:workers"
EXECUTOR_GROUP = "executors"
ORCH_GROUP = "orchestrator"


def halt_key_tenant(tenant_id: str) -> str:
    return f"asvas:halt:tenant:{tenant_id}"


def halt_key_assessment(assessment_id: str) -> str:
    return f"asvas:halt:assessment:{assessment_id}"


@functools.lru_cache
def get_redis(url: str | None = None) -> redis.Redis:
    s = get_settings()
    u = url or s.redis_url
    if u.startswith("rediss://"):
        # Verified TLS: CA from config (dev CA) or system roots; hostname checked; TLS 1.2+ (server enforces 1.3).
        return redis.Redis.from_url(u, decode_responses=True, ssl_cert_reqs="required",
                                    ssl_ca_certs=s.redis_ca_file or None, ssl_check_hostname=True)
    if s.env == "production":
        raise RuntimeError("ASVAS_REDIS_URL must use rediss:// (TLS) outside development")
    return redis.Redis.from_url(u, decode_responses=True)


def ensure_groups(r: redis.Redis) -> None:
    for stream, group in ((JOBS, EXECUTOR_GROUP), (RESULTS, ORCH_GROUP), (ORCH, ORCH_GROUP)):
        try:
            r.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise


def _mac(purpose: str, data: bytes) -> str:
    return hmac.new(get_settings().derived_key(purpose), data, hashlib.sha256).hexdigest()


def _mac_ok(purpose: str, data: bytes, sig: str) -> bool:
    return hmac.compare_digest(_mac(purpose, data), sig or "")


def encode_envelope(envelope: dict[str, Any]) -> dict[str, str]:
    """Stream fields for one job: base64 protobuf JobEnvelope + HMAC over the serialized bytes."""
    data = wire.envelope_to_pb(envelope).SerializeToString(deterministic=True)
    return {"envelope_pb": wire.b64(data), "sig": _mac("envelope", data)}


def decode_envelope(fields: dict[str, str]) -> dict[str, Any] | None:
    data = wire.unb64(fields.get("envelope_pb", ""))
    if not _mac_ok("envelope", data, fields.get("sig", "")):
        return None
    return wire.envelope_from_pb(wire.parse(wire.pb.JobEnvelope, data))


# Upper bound for one serialized JobResult (base64). Executor caps per-response excerpts and request counts, so
# legitimate results are far smaller; anything larger is dropped before decoding.
MAX_RESULT_B64 = 8 * 1024 * 1024


def encode_result(result: dict[str, Any]) -> dict[str, str]:
    data = wire.result_to_pb(result).SerializeToString(deterministic=True)
    return {"result_pb": wire.b64(data), "sig": _mac("result", data)}


def verify_result(fields: dict[str, str]) -> dict[str, Any] | None:
    """Authenticate and decode a JobResult. None if the signature is wrong or the payload is malformed."""
    raw = fields.get("result_pb", "")
    if len(raw) > MAX_RESULT_B64:  # DA-15: bounded parse instead of buffering arbitrarily large results
        return None
    try:
        data = wire.unb64(raw)
        if not _mac_ok("result", data, fields.get("sig", "")):
            return None
        return wire.result_from_pb(wire.parse(wire.pb.JobResult, data))
    except wire.WireError:
        return None


def publish_job(r: redis.Redis, envelope: dict[str, Any]) -> str:
    return r.xadd(JOBS, encode_envelope(envelope), maxlen=100000, approximate=True)


def signed_control(message: dict[str, Any]) -> tuple[bytes, str]:
    data = wire.control_to_pb({**message, "issued_unix": int(time.time())}).SerializeToString(deterministic=True)
    return data, _mac("control", data)


def publish_control(r: redis.Redis, message: dict[str, Any]) -> tuple[bytes, str]:
    data, sig = signed_control(message)
    r.xadd(CONTROL, {"control_pb": wire.b64(data), "sig": sig}, maxlen=10000, approximate=True)
    return data, sig


def publish_orchestrator(r: redis.Redis, message: dict[str, Any]) -> None:
    r.xadd(ORCH, {"message": json.dumps(message)}, maxlen=10000, approximate=True)


def approval_token(approval_id: str, binding: str, expires_unix: int) -> str:
    return hmac_hex(get_settings().derived_key("approval"),
                    canonical_json({"approval_id": approval_id, "binding_hash": binding, "expires_unix": expires_unix}))
