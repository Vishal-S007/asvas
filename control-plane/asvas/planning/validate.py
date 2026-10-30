"""Deterministic validation of model proposals (spec pp. 9, 47-49, 72). Runs outside any model influence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from asvas.canonical import canonical_json, sha256_hex
from asvas.planning.providers import PlanProposal, PlanStep
from asvas.scope import Scope, check_target, resolve
from asvas.tools import REGISTRY, ToolParamError, validate_params


def fingerprint(tool_id: str, target: dict, params: dict, salt: str = "") -> str:
    return sha256_hex(canonical_json({"tool_id": tool_id, "target": target, "params": params, "salt": salt}))


def tarjan_scc(nodes: list[str], edges: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan's strongly connected components (iterative). Components with >1 node or a self-loop are cycles."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    out: list[list[str]] = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(edges.get(root, [])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(edges.get(w, []))))
                    advanced = True
                    break
                if w in on_stack:
                    low[v] = min(low[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                out.append(comp)
    return out


@dataclass
class ValidatedStep:
    step: PlanStep
    target: dict[str, Any]
    params: dict[str, Any]
    resolved_ips: list[str]
    fingerprint: str
    depth: int


@dataclass
class ValidationOutcome:
    accepted: list[ValidatedStep] = field(default_factory=list)
    rejected: list[tuple[PlanStep, list[str]]] = field(default_factory=list)


def validate_proposal(proposal: PlanProposal, scope: Scope, policy: dict, existing_fingerprints: set[str],
                      existing_job_count: int, round_no: int,
                      resolve_fn: Callable[[str], list[str]] = resolve) -> ValidationOutcome:
    out = ValidationOutcome()
    ids = [s.step_id for s in proposal.steps]
    dup_ids = {i for i in ids if ids.count(i) > 1}
    edges = {s.step_id: [d for d in s.depends_on] for s in proposal.steps}
    cyclic: set[str] = set()
    for comp in tarjan_scc(ids, edges):
        if len(comp) > 1 or comp[0] in edges.get(comp[0], []):
            cyclic.update(comp)

    def depth_of(sid: str, seen: frozenset = frozenset()) -> int:
        if sid in seen or sid not in edges:
            return 0
        return 1 + max((depth_of(d, seen | {sid}) for d in edges[sid]), default=0)

    seen_fp: set[str] = set()
    budget_left = policy["max_jobs"] - existing_job_count
    for s in proposal.steps:
        reasons: list[str] = []
        if s.step_id in dup_ids:
            reasons.append("duplicate step_id")
        if s.step_id in cyclic:
            reasons.append("dependency cycle detected (Tarjan SCC)")
        missing = [d for d in s.depends_on if d not in edges]
        if missing:
            reasons.append(f"unknown dependencies {missing}")
        depth = round_no + depth_of(s.step_id)
        if depth > policy["max_plan_depth"]:
            reasons.append(f"plan depth {depth} exceeds max_plan_depth {policy['max_plan_depth']}")
        spec = REGISTRY.get(s.tool_id)
        params: dict[str, Any] = {}
        if spec is None:
            reasons.append(f"tool {s.tool_id!r} is not in the tool registry")
        else:
            if s.tool_id not in policy["allowed_tools"]:
                reasons.append(f"tool {s.tool_id} is not allowed by the testing policy")
            try:
                params = validate_params(s.tool_id, s.params)
            except ToolParamError as e:
                reasons.append(f"invalid params: {e}")
        target = {"scheme": s.target.scheme.lower(), "host": s.target.host.strip().lower().rstrip("."),
                  "port": s.target.port}
        ips: list[str] = []
        scope_reasons = check_target(scope, target["scheme"], target["host"], target["port"], resolve_fn)
        reasons.extend(scope_reasons)
        if not scope_reasons:
            ips = resolve_fn(target["host"])
        fp = fingerprint(s.tool_id, target, params)
        if fp in existing_fingerprints or fp in seen_fp:
            reasons.append("loop/duplicate: identical action already planned or executed")
        if not reasons and budget_left <= 0:
            reasons.append("job budget (max_jobs) exhausted")
        if reasons:
            out.rejected.append((s, reasons))
            continue
        seen_fp.add(fp)
        budget_left -= 1
        out.accepted.append(ValidatedStep(s, target, params, ips, fp, depth))
    return out
