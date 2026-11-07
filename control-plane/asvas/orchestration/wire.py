"""Protobuf wire format for the control <-> execution contract (proto/asvasrpc/execution/v1/execution.proto).

Payloads cross Redis Streams as base64 of the serialized message plus a hex HMAC-SHA256 computed over the
*serialized bytes* (not over a re-encoding), so both planes authenticate exactly what was sent.
Receivers reject messages that carry unknown fields.
"""

from __future__ import annotations

import base64
from typing import Any

from google.protobuf.message import DecodeError, Message
from google.protobuf.unknown_fields import UnknownFieldSet

from asvasrpc.execution.v1 import execution_pb2 as pb

ENVELOPE_VERSION = 2
_STATUS = {v: k.removeprefix("JOB_STATUS_") for k, v in pb.JobStatus.items()}
_STATUS_REV = {v: k for k, v in _STATUS.items()}
_PARAM_FIELD = {"http.security_headers": "security_headers", "http.allowed_methods": "allowed_methods",
                "tls.configuration": "tls"}


class WireError(ValueError):
    pass


def has_unknown_fields(msg: Message) -> bool:
    if len(UnknownFieldSet(msg)):
        return True
    for fd, value in msg.ListFields():
        if fd.message_type is None or fd.message_type.GetOptions().map_entry:
            continue
        items = value if fd.is_repeated else [value]
        if any(has_unknown_fields(v) for v in items):
            return True
    return False


def parse(cls: type[Message], data: bytes) -> Message:
    m = cls()
    try:
        m.ParseFromString(data)
    except DecodeError as e:
        raise WireError(f"undecodable {cls.__name__}") from e
    if has_unknown_fields(m):
        raise WireError(f"{cls.__name__} carries unknown fields")
    return m


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except (ValueError, TypeError) as e:
        raise WireError("payload is not valid base64") from e


# ---------------------------------------------------------------- envelope

def envelope_to_pb(e: dict[str, Any]) -> pb.JobEnvelope:
    s, p = e["scope"], e["policy"]
    m = pb.JobEnvelope(
        version=ENVELOPE_VERSION, job_id=e["job_id"], attempt=e["attempt"], tenant_id=e["tenant_id"],
        assessment_id=e["assessment_id"], tool_id=e["tool_id"], risk_tier=e["risk_tier"], category=e["category"],
        target=pb.Target(**e["target"]), max_requests=e["max_requests"],
        requests_per_second=e["requests_per_second"], timeout_seconds=e["timeout_seconds"],
        deadline_unix=e["deadline_unix"], issued_unix=e["issued_unix"],
        scope=pb.Scope(targets=[pb.ScopeTarget(**t) for t in s["targets"]], allowed_cidrs=s["allowed_cidrs"],
                       excluded_cidrs=s.get("excluded_cidrs", []),
                       authorization=pb.Authorization(**{k: str(v) for k, v in s["authorization"].items()})),
        policy=pb.TestingPolicy(**{k: v for k, v in p.items() if k in pb.TestingPolicy.DESCRIPTOR.fields_by_name}),
    )
    field = _PARAM_FIELD.get(e["tool_id"])
    if field is None:
        raise WireError(f"no wire mapping for tool {e['tool_id']!r}")
    getattr(m, field).CopyFrom(getattr(pb, type(getattr(m, field)).__name__)(**e["params"]))
    if e.get("approval"):
        m.approval.CopyFrom(pb.Approval(**e["approval"]))
    return m


def envelope_from_pb(m: pb.JobEnvelope) -> dict[str, Any]:
    from google.protobuf.json_format import MessageToDict
    d = MessageToDict(m, preserving_proto_field_name=True, always_print_fields_with_no_presence=True)
    which = m.WhichOneof("params")
    d["params"] = d.pop(which) if which else {}
    for f in _PARAM_FIELD.values():
        d.pop(f, None)
    for k in ("deadline_unix", "issued_unix"):
        d[k] = int(d[k])
    if m.HasField("approval"):
        d["approval"]["expires_unix"] = int(d["approval"]["expires_unix"])
    else:
        d["approval"] = None
    return d


# ---------------------------------------------------------------- result

def result_from_pb(m: pb.JobResult) -> dict[str, Any]:
    """Convert to the dict shape the orchestrator and evidence store use (unchanged from the JSON era)."""
    def exch(x: pb.Exchange) -> dict[str, Any]:
        r = x.request
        out: dict[str, Any] = {
            "seq": x.seq,
            "request": {"method": r.method, "url": r.url, "scheme": r.scheme, "host": r.host, "port": r.port,
                        "path": r.path, "resolved_ip": r.resolved_ip},
            "response": None, "redirect": None, "error": x.error if x.HasField("error") else None,
            "started_unix_ms": x.started_unix_ms, "duration_ms": x.duration_ms,
        }
        if x.HasField("response"):
            rs = x.response
            out["response"] = {"status": rs.status, "headers": [[h.name, h.value] for h in rs.headers],
                               "body_sha256": rs.body_sha256, "body_len": rs.body_len,
                               "body_truncated": rs.body_truncated, "body_excerpt": rs.body_excerpt}
            if rs.tls_version:
                out["response"]["tls_version"] = rs.tls_version
        if x.HasField("redirect"):
            out["redirect"] = {"location": x.redirect.location, "decision": x.redirect.decision}
            if x.redirect.reason:
                out["redirect"]["reason"] = x.redirect.reason
        if x.HasField("tls"):
            t = x.tls
            out["tls"] = {f.name: (list(v) if f.is_repeated else v)
                          for f in t.DESCRIPTOR.fields for v in [getattr(t, f.name)]}
        return out

    pd = m.policy_decision
    return {
        "job_id": m.job_id, "attempt": m.attempt, "tenant_id": m.tenant_id, "assessment_id": m.assessment_id,
        "worker_id": m.worker_id, "status": _STATUS[m.status], "error": m.error or None,
        "policy_decision": {"allow": pd.allow, "require_approval": pd.require_approval,
                            "approval_satisfied": pd.approval_satisfied, "deny_reasons": list(pd.deny_reasons),
                            "error": pd.error or None, "engine": pd.engine, "plane": pd.plane}
        if m.HasField("policy_decision") else None,
        "backend": m.backend, "egress_mode": m.egress_mode, "requests_used": m.requests_used,
        "exchanges": [exch(x) for x in m.exchanges], "sandbox_attestation": dict(m.sandbox_attestation),
        "started_unix": m.started_unix, "finished_unix": m.finished_unix,
    }


def result_to_pb(d: dict[str, Any]) -> pb.JobResult:
    """Used by tests and simulators; the real producer is the Go executor."""
    m = pb.JobResult(job_id=d["job_id"], attempt=d["attempt"], tenant_id=d["tenant_id"],
                     assessment_id=d["assessment_id"], worker_id=d.get("worker_id", ""),
                     status=_STATUS_REV[d["status"]], error=d.get("error") or "", backend=d.get("backend", ""),
                     egress_mode=d.get("egress_mode", ""), requests_used=d.get("requests_used", 0))
    if d.get("policy_decision"):
        p = d["policy_decision"]
        m.policy_decision.CopyFrom(pb.PolicyDecision(allow=p.get("allow", False),
                                                     deny_reasons=p.get("deny_reasons", [])))
    for x in d.get("exchanges", []):
        e = m.exchanges.add(seq=x["seq"], request=pb.Request(**x["request"]),
                            started_unix_ms=x.get("started_unix_ms", 0), duration_ms=x.get("duration_ms", 0))
        if x.get("response"):
            rs = dict(x["response"])
            headers = rs.pop("headers", [])
            e.response.CopyFrom(pb.Response(headers=[pb.Header(name=k, value=v) for k, v in headers], **rs))
        if x.get("redirect"):
            e.redirect.CopyFrom(pb.Redirect(**x["redirect"]))
        if x.get("tls"):
            e.tls.CopyFrom(pb.TLSInfo(**x["tls"]))
        if x.get("error") is not None:
            e.error = x["error"]
    return m


# ---------------------------------------------------------------- control

_CONTROL = {"cancel_assessment": pb.CONTROL_TYPE_CANCEL_ASSESSMENT, "emergency_stop": pb.CONTROL_TYPE_EMERGENCY_STOP}


def control_to_pb(msg: dict[str, Any]) -> pb.ControlMessage:
    return pb.ControlMessage(type=_CONTROL[msg["type"]], tenant_id=msg["tenant_id"],
                             assessment_id=msg.get("assessment_id", ""), reason=msg.get("reason", ""),
                             issued_unix=int(msg.get("issued_unix", 0)))
