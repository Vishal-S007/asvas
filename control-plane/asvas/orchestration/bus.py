"""Redis Streams event bus (spec pp. 23, 66-67, 81) and signed job envelopes."""

from __future__ import annotations

import functools
import json
from typing import Any

import redis

from asvas.canonical import canonical_json, hmac_hex, hmac_verify
from asvas.config import get_settings

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
    return redis.Redis.from_url(url or get_settings().redis_url, decode_responses=True)


def ensure_groups(r: redis.Redis) -> None:
    for stream, group in ((JOBS, EXECUTOR_GROUP), (RESULTS, ORCH_GROUP), (ORCH, ORCH_GROUP)):
        try:
            r.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise


def sign_envelope(envelope: dict[str, Any]) -> tuple[str, str]:
    body = canonical_json(envelope)
    return body, hmac_hex(get_settings().derived_key("envelope"), body)


def verify_result(body: str, sig: str) -> dict[str, Any] | None:
    if not hmac_verify(get_settings().derived_key("result"), body, sig):
        return None
    return json.loads(body)


def publish_job(r: redis.Redis, envelope: dict[str, Any]) -> str:
    body, sig = sign_envelope(envelope)
    return r.xadd(JOBS, {"envelope": body, "sig": sig}, maxlen=100000, approximate=True)


def publish_control(r: redis.Redis, message: dict[str, Any]) -> None:
    body = canonical_json(message)
    r.xadd(CONTROL, {"message": body, "sig": hmac_hex(get_settings().derived_key("control"), body)},
           maxlen=10000, approximate=True)


def publish_orchestrator(r: redis.Redis, message: dict[str, Any]) -> None:
    r.xadd(ORCH, {"message": json.dumps(message)}, maxlen=10000, approximate=True)


def approval_token(approval_id: str, binding: str, expires_unix: int) -> str:
    return hmac_hex(get_settings().derived_key("approval"),
                    canonical_json({"approval_id": approval_id, "binding_hash": binding, "expires_unix": expires_unix}))
