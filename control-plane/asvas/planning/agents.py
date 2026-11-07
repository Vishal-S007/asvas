"""Specialised planning sub-agents with restricted tool sub-schemas (requirement PL-10; spec pp. 2, 68-70).

Instead of one planner with every capability, each round is planned by a fixed sequence of sub-agents. Each
agent sees only the tools of its role (its sub-schema of the tool layer) and its proposals are validated against
that same sub-schema: a step naming a tool outside the proposing agent's role is rejected, even if the testing
policy would allow the tool.

Implemented: Discovery (RECON tools) and Configuration Verifier (CONFIG_VERIFIER tools). The spec's Identity
Analyst has no non-destructive tools in this system yet, so it is not instantiated.
"""

from __future__ import annotations

from dataclasses import dataclass

from asvas.tools import REGISTRY


@dataclass(frozen=True)
class AgentSpec:
    name: str
    role: str
    prefix: str
    brief: str


AGENTS: tuple[AgentSpec, ...] = (
    AgentSpec("discovery", "RECON", "disc", "Discover exposed services and advertised behaviour of in-scope targets."),
    AgentSpec("config_verifier", "CONFIG_VERIFIER", "conf",
              "Verify security configuration (headers, cookies, TLS) of in-scope services."),
)
BY_NAME = {a.name: a for a in AGENTS}


def tools_for(agent: AgentSpec, tools: list[dict]) -> list[dict]:
    return [t for t in tools if t.get("agent_role") == agent.role]


def tool_allowed_for(agent_name: str | None, tool_id: str) -> bool:
    spec, agent = REGISTRY.get(tool_id), BY_NAME.get(agent_name or "")
    return bool(spec and agent and spec.agent_role == agent.role)
