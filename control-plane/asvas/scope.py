"""Assessment scope + testing policy models and deterministic scope enforcement (spec pp. 46-48)."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from asvas.config import get_settings

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")

# Never valid targets regardless of scope: link-local/metadata, "this" network, multicast, reserved, broadcast.
FORBIDDEN_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",
)]
LOOPBACK_NETWORKS = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]

ToolId = Literal["http.security_headers", "http.allowed_methods", "tls.configuration"]
RiskTier = Literal["low", "medium", "high"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Authorization(Strict):
    """Who authorized testing, and for how long. Execution is refused outside this window."""
    statement: str = Field(min_length=20, max_length=2000)
    reference: str = Field(min_length=3, max_length=200, description="Ticket / engagement letter id")
    authorized_by: str = Field(min_length=3, max_length=200)
    valid_from: dt.datetime
    valid_until: dt.datetime

    @model_validator(mode="after")
    def _window(self) -> Authorization:
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("authorization window must be timezone-aware")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        if self.valid_until - self.valid_from > dt.timedelta(days=90):
            raise ValueError("authorization window may not exceed 90 days")
        return self


class TargetSpec(Strict):
    host: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=16)
    schemes: list[Literal["http", "https"]] = Field(default=["http", "https"], min_length=1)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            pass
        if not HOSTNAME_RE.match(v):
            raise ValueError("host must be an IP address or a valid DNS hostname (no wildcards, no URLs)")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(p < 1 or p > 65535 for p in v):
            raise ValueError("ports must be 1-65535")
        return sorted(set(v))

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


class Scope(Strict):
    targets: list[TargetSpec] = Field(min_length=1, max_length=64)
    allowed_cidrs: list[str] = Field(min_length=1, max_length=64,
                                     description="Every resolved address of every target must be inside these")
    excluded_cidrs: list[str] = Field(default_factory=list, max_length=64)
    authorization: Authorization

    @field_validator("allowed_cidrs", "excluded_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        out = []
        for c in v:
            net = ipaddress.ip_network(c, strict=False)
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise ValueError(f"CIDR {c} is too broad (min /16 IPv4, /48 IPv6)")
            out.append(str(net))
        return out

    @model_validator(mode="after")
    def _consistency(self) -> Scope:
        nets = [ipaddress.ip_network(c) for c in self.allowed_cidrs]
        for t in self.targets:
            if t.is_ip and not any(ipaddress.ip_address(t.host) in n for n in nets):
                raise ValueError(f"target {t.host} is not inside allowed_cidrs")
        return self


class TestingPolicy(Strict):
    __test__ = False  # not a pytest test class
    allowed_tools: list[ToolId] = Field(default=["http.security_headers"], min_length=1)
    approval_required_risk_tiers: list[RiskTier] = Field(default=["high"])
    max_requests_per_second: int = Field(default=2, ge=1, le=10)
    max_total_requests: int = Field(default=100, ge=1, le=500)
    max_concurrency: int = Field(default=2, ge=1, le=4)
    job_timeout_seconds: int = Field(default=20, ge=5, le=30)  # spec p.14: validation < 30 s
    max_wall_clock_minutes: int = Field(default=30, ge=1, le=720)  # spec p.50: < 12 h per segment
    max_tokens: int = Field(default=20000, ge=0, le=500000)
    max_planning_rounds: int = Field(default=3, ge=1, le=5)
    max_plan_depth: int = Field(default=15, ge=1, le=15)  # spec p.9: D_max = 15
    max_jobs: int = Field(default=50, ge=1, le=200)
    max_attempts: int = Field(default=2, ge=1, le=3)
    # SC-08: refuse to run unless the executor proves kernel egress filtering (nftables) is active.
    require_kernel_egress: bool = False

    @model_validator(mode="after")
    def _high_always(self) -> TestingPolicy:
        if "high" not in self.approval_required_risk_tiers:
            raise ValueError("high-risk actions always require human approval (spec p.4)")
        return self


class ScopeViolation(Exception):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def ip_violations(ip_str: str, scope: Scope, port: int | None = None) -> list[str]:
    s = get_settings()
    ip = ipaddress.ip_address(ip_str)
    reasons: list[str] = []
    if any(ip in n for n in FORBIDDEN_NETWORKS):
        reasons.append(f"{ip} is in a globally forbidden network")
    if any(ip in n for n in LOOPBACK_NETWORKS):
        if not s.allow_loopback_targets:
            reasons.append(f"{ip} is loopback and loopback targets are disabled")
        elif port is not None and port in s.protected_ports:
            reasons.append(f"port {port} on loopback belongs to the platform and is protected")
    if not any(ip in ipaddress.ip_network(c) for c in scope.allowed_cidrs):
        reasons.append(f"{ip} is outside allowed_cidrs")
    if any(ip in ipaddress.ip_network(c) for c in scope.excluded_cidrs):
        reasons.append(f"{ip} is inside excluded_cidrs")
    return reasons


def resolve(host: str) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def check_target(scope: Scope, scheme: str, host: str, port: int, resolve_fn=resolve) -> list[str]:
    """Deterministic scope check used before any proposal becomes a job. Returns violation reasons."""
    host = host.strip().lower().rstrip(".")
    matches = [t for t in scope.targets if t.host == host]
    if not matches:
        return [f"host {host!r} is not a scope target"]
    t = matches[0]
    reasons = []
    if port not in t.ports:
        reasons.append(f"port {port} is not in scope for {host}")
    if scheme not in t.schemes:
        reasons.append(f"scheme {scheme} is not in scope for {host}")
    try:
        ips = resolve_fn(host)
    except OSError as e:
        return reasons + [f"cannot resolve {host}: {e}"]
    if not ips:
        reasons.append(f"{host} resolved to no addresses")
    for ip in ips:
        reasons.extend(ip_violations(ip, scope, port))
    return reasons


def check_authorization_window(scope: Scope, now: dt.datetime | None = None) -> list[str]:
    now = now or dt.datetime.now(dt.UTC)
    a = scope.authorization
    if now < a.valid_from:
        return ["authorization window has not started"]
    if now >= a.valid_until:
        return ["authorization window has expired"]
    return []
