"""Protobuf wire contract (PO-06): signatures over serialized bytes, unknown-field rejection, typed params."""

import pytest

from asvas.orchestration import bus, wire
from asvas.orchestration.wire import pb

ENV = {
    "job_id": "11111111-1111-4111-8111-111111111111", "attempt": 1,
    "tenant_id": "22222222-2222-4222-8222-222222222222", "assessment_id": "33333333-3333-4333-8333-333333333333",
    "tool_id": "http.security_headers", "risk_tier": "low", "category": "non_destructive",
    "target": {"scheme": "http", "host": "127.0.0.1", "port": 18080},
    "params": {"path": "/", "method": "GET", "max_redirects": 3},
    "max_requests": 4, "requests_per_second": 2, "timeout_seconds": 20, "deadline_unix": 1900000000,
    "issued_unix": 1890000000,
    "scope": {"targets": [{"host": "127.0.0.1", "ports": [18080], "schemes": ["http"]}],
              "allowed_cidrs": ["127.0.0.1/32"], "excluded_cidrs": [],
              "authorization": {"statement": "s" * 20, "reference": "REF", "authorized_by": "me",
                                "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-02-01T00:00:00Z"}},
    "policy": {"allowed_tools": ["http.security_headers"], "approval_required_risk_tiers": ["high"],
               "max_requests_per_second": 2, "job_timeout_seconds": 20, "require_kernel_egress": False},
    "approval": None,
}


def test_envelope_round_trip_and_signature():
    fields = bus.encode_envelope(ENV)
    assert set(fields) == {"envelope_pb", "sig"}
    back = bus.decode_envelope(fields)
    assert back["params"] == ENV["params"] and back["target"] == ENV["target"] and back["approval"] is None
    assert back["deadline_unix"] == ENV["deadline_unix"] and back["scope"]["allowed_cidrs"] == ["127.0.0.1/32"]
    data = bytearray(wire.unb64(fields["envelope_pb"]))
    data[-1] ^= 1
    assert bus.decode_envelope({"envelope_pb": wire.b64(bytes(data)), "sig": fields["sig"]}) is None


def test_typed_params_only():
    with pytest.raises(wire.WireError):
        wire.envelope_to_pb({**ENV, "tool_id": "shell.exec"})
    with pytest.raises(ValueError):  # free-form keys cannot be expressed in the typed contract
        wire.envelope_to_pb({**ENV, "params": {"path": "/", "cmd": "id"}})
    m = wire.envelope_to_pb({**ENV, "tool_id": "tls.configuration", "params": {"expiry_warning_days": 30}})
    assert m.WhichOneof("params") == "tls"


def test_unknown_fields_rejected_even_when_signed():
    data = wire.envelope_to_pb(ENV).SerializeToString()
    smuggled = data + b"\xfa\x06\x02id"  # field 111, length-delimited "id"
    with pytest.raises(wire.WireError, match="unknown fields"):
        wire.parse(pb.JobEnvelope, smuggled)
    sig = bus._mac("result", smuggled)
    assert bus.verify_result({"result_pb": wire.b64(smuggled), "sig": sig}) is None


def test_result_round_trip_preserves_evidence_shape():
    ex = {"seq": 0, "request": {"method": "GET", "url": "u", "scheme": "http", "host": "h", "port": 1, "path": "/",
                                "resolved_ip": "127.0.0.1"},
          "response": {"status": 200, "headers": [["Server", "x"], ["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
                       "body_sha256": "0" * 64, "body_len": 1, "body_truncated": False, "body_excerpt": "<x>"},
          "redirect": {"location": "http://198.51.100.7/", "decision": "blocked", "reason": "outside scope"},
          "error": None, "started_unix_ms": 5, "duration_ms": 6}
    fields = bus.encode_result({"job_id": "j", "attempt": 1, "tenant_id": "t", "assessment_id": "a",
                                "status": "SUCCEEDED", "exchanges": [ex]})
    got = bus.verify_result(fields)
    assert got["status"] == "SUCCEEDED" and got["exchanges"][0] == ex  # duplicate headers kept, order kept
    assert bus.verify_result({**fields, "sig": "0" * 64}) is None
    assert bus.verify_result({"result_pb": "!!!", "sig": "x"}) is None
