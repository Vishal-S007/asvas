"""Tool Abstraction Layer registry (spec pp. 2-3, 27-28, 74-76).

Only the operations listed here exist. There is no shell tool and no free-form payload field. The Go
execution plane carries an identical registry (execution-plane/internal/checks) and validates again.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

PATH_RE = re.compile(r"^/[A-Za-z0-9/._~\-]{0,255}$")


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _validate_path(v: str) -> str:
    if not PATH_RE.match(v) or ".." in v:
        raise ValueError("path must be an absolute URL path of safe characters (no query, no '..')")
    return v


class SecurityHeadersParams(_Params):
    path: str = Field(default="/")
    method: Literal["GET", "HEAD"] = "GET"
    max_redirects: int = Field(default=3, ge=0, le=3)

    _path = field_validator("path")(classmethod(lambda cls, v: _validate_path(v)))


class AllowedMethodsParams(_Params):
    path: str = Field(default="/")

    _path = field_validator("path")(classmethod(lambda cls, v: _validate_path(v)))


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    title: str
    risk_tier: Literal["low", "medium", "high"]
    category: Literal["non_destructive"]
    agent_role: Literal["RECON", "CONFIG_VERIFIER"]
    params_model: type[_Params]
    max_requests: int
    description: str


REGISTRY: dict[str, ToolSpec] = {
    "http.security_headers": ToolSpec(
        "http.security_headers", "HTTP security header & cookie configuration", "low", "non_destructive",
        "CONFIG_VERIFIER", SecurityHeadersParams, 4,
        "Issues GET/HEAD to one in-scope URL, follows only in-scope redirects, records headers as evidence."),
    "http.allowed_methods": ToolSpec(
        "http.allowed_methods", "Advertised HTTP methods (OPTIONS)", "medium", "non_destructive",
        "RECON", AllowedMethodsParams, 1,
        "Sends a single OPTIONS request and records the Allow header. Never sends the advertised methods."),
}


class ToolParamError(ValueError):
    pass


def validate_params(tool_id: str, params: dict) -> dict:
    spec = REGISTRY.get(tool_id)
    if spec is None:
        raise ToolParamError(f"unknown tool {tool_id!r}")
    if not isinstance(params, dict):
        raise ToolParamError("params must be an object")
    try:
        return spec.params_model.model_validate(params).model_dump()
    except ValidationError as e:
        raise ToolParamError("; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())) from e


def catalog() -> list[dict]:
    return [
        {"tool_id": s.tool_id, "title": s.title, "risk_tier": s.risk_tier, "category": s.category,
         "agent_role": s.agent_role, "max_requests": s.max_requests, "description": s.description,
         "params_schema": s.params_model.model_json_schema()}
        for s in REGISTRY.values()
    ]
