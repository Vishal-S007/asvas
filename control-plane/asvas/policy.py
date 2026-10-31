"""OPA client (control-plane side). Fails closed: any error => deny."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from asvas.config import get_settings


@dataclass
class PolicyDecision:
    allow: bool
    require_approval: bool
    approval_satisfied: bool
    deny_reasons: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"allow": self.allow, "require_approval": self.require_approval,
                "approval_satisfied": self.approval_satisfied, "deny_reasons": self.deny_reasons,
                "error": self.error, "engine": "opa", "plane": "control"}


def build_input(*, tool_id: str, risk_tier: str, category: str, max_requests: int, rps: int,
                timeout_seconds: int, target: dict, resolved_ips: list[str], scope: dict, policy: dict,
                approval: dict | None, halted: bool) -> dict:
    s = get_settings()
    return {
        "action": {"tool_id": tool_id, "risk_tier": risk_tier, "category": category,
                   "max_requests": max_requests, "requests_per_second": rps, "timeout_seconds": timeout_seconds},
        "target": {**target, "resolved_ips": resolved_ips},
        "scope": scope,
        "policy": policy,
        "approval": approval or {"present": False},
        "context": {"now_unix": int(time.time()), "loopback_allowed": s.allow_loopback_targets,
                    "protected_ports": s.protected_ports, "halted": halted, "plane": "control"},
    }


class OpaClient:
    def __init__(self, url: str | None = None, transport: httpx.BaseTransport | None = None):
        s = get_settings()
        self.url = (url or s.opa_url).rstrip("/")
        self._client = httpx.Client(timeout=s.opa_timeout_seconds, transport=transport, trust_env=False)

    def evaluate(self, policy_input: dict) -> PolicyDecision:
        try:
            r = self._client.post(f"{self.url}/v1/data/asvas/decision/decision", json={"input": policy_input})
            r.raise_for_status()
            result = r.json().get("result")
            if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
                raise ValueError("OPA returned no decision document (policy not loaded?)")
            return PolicyDecision(result["allow"], bool(result.get("require_approval")),
                                  bool(result.get("approval_satisfied")), list(result.get("deny_reasons", [])))
        except Exception as e:  # noqa: BLE001 - fail closed on every error
            return PolicyDecision(False, False, False, ["policy engine unavailable: deny by default"], str(e))

    def health(self) -> dict:
        try:
            r = self._client.get(f"{self.url}/health?bundles=false")
            ok = r.status_code == 200
            probe = self.evaluate({})
            loaded = probe.error is None
            return {"reachable": ok, "policy_loaded": loaded, "url": self.url}
        except Exception as e:  # noqa: BLE001
            return {"reachable": False, "policy_loaded": False, "url": self.url, "error": str(e)}
