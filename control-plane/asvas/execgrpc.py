"""Client for the executors' ExecutorService (gRPC over mutual TLS 1.3; requirement PO-06/CP-10 partial).

Executors advertise their address in Redis heartbeats. That address is not trusted on its own: the server must
present a certificate issued by the configured CA, and the control plane authenticates with its own client
certificate. Control messages carry the same HMAC as the Redis control stream.
"""

from __future__ import annotations

import json
import time
from typing import Any

import grpc

from asvas.config import get_settings
from asvasrpc.execution.v1 import execution_pb2 as pb
from asvasrpc.execution.v1 import execution_pb2_grpc as pbg

TIMEOUT = 2.0


def configured() -> bool:
    s = get_settings()
    return bool(s.executor_tls_ca and s.executor_tls_cert and s.executor_tls_key)


def _creds() -> grpc.ChannelCredentials:
    s = get_settings()
    with open(s.executor_tls_ca, "rb") as ca, open(s.executor_tls_cert, "rb") as crt, open(s.executor_tls_key, "rb") as k:
        return grpc.ssl_channel_credentials(root_certificates=ca.read(), private_key=k.read(), certificate_chain=crt.read())


def _stub(addr: str) -> tuple[grpc.Channel, pbg.ExecutorServiceStub]:
    ch = grpc.secure_channel(addr, _creds(), options=[("grpc.enable_retries", 0)])
    return ch, pbg.ExecutorServiceStub(ch)


def live_executors(r) -> list[dict[str, Any]]:
    out = []
    for wid, raw in r.hgetall("asvas:workers").items():
        w = json.loads(raw)
        if w.get("grpc_addr") and time.time() - w.get("heartbeat_unix", 0) <= get_settings().worker_stale_seconds:
            out.append({"worker_id": wid, "addr": w["grpc_addr"]})
    return out


def probe(addr: str) -> dict[str, Any]:
    if not configured():
        return {"reachable": False, "detail": "control-plane TLS client material not configured"}
    try:
        ch, stub = _stub(addr)
        with ch:
            st = stub.GetStatus(pb.GetStatusRequest(), timeout=TIMEOUT)
        return {"reachable": True, "mtls": True, "worker_id": st.worker_id, "running_jobs": st.running_jobs,
                "egress_mode": st.egress_mode}
    except grpc.RpcError as e:
        return {"reachable": False, "detail": f"{e.code().name}: {e.details()}"}
    except OSError as e:
        return {"reachable": False, "detail": f"TLS material unreadable: {e}"}


def broadcast_control(r, data: bytes, sig: str) -> list[dict[str, Any]]:
    """Best-effort direct delivery of a signed control message to every live executor."""
    if not configured():
        return []
    results = []
    for w in live_executors(r):
        try:
            ch, stub = _stub(w["addr"])
            with ch:
                ack = stub.Control(pb.SignedControl(control_message=data, sig=sig), timeout=TIMEOUT)
            results.append({"worker_id": w["worker_id"], "ok": True, "jobs_signalled": ack.jobs_signalled})
        except grpc.RpcError as e:
            results.append({"worker_id": w["worker_id"], "ok": False, "detail": e.code().name})
    return results
