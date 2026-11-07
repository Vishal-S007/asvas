# ASVAS Architecture (Milestone 1)

Spec basis: PDF pp. 1-4, 66-68 (modular monolith + isolated execution plane), 74-77 (tool mediation, data flow).

## Planes and trust boundaries

```
 ┌──────────────────────── MANAGEMENT PLANE ────────────────────────┐
 │ React dashboard (dashboard/)  ──HTTPS/JWT──►  FastAPI /api/v1     │
 └───────────────────────────────────────────────────────────────────┘
                                │
 ┌──────────────── CONTROL PLANE (modular monolith, Python) ─────────┐
 │ asvas.api          REST gateway, auth, RBAC, problem+json, ratelim│
 │ asvas.assessments  scope + testing policy, state machine          │
 │ asvas.planning     LangGraph graph, ModelProvider, plan validator │
 │ asvas.policy       OPA client (sidecar) + deterministic prechecks │
 │ asvas.orchestration job lifecycle, approvals, dispatcher, reaper  │
 │ asvas.evidence     evidence store, findings, retests              │
 │ asvas.reporting    JSON/Markdown reports                          │
 │ asvas.audit        hash-chained append-only ledger                │
 │      │ PostgreSQL 16 (RLS)   │ Redis Streams    │ OPA server      │
 └──────┼───────────────────────┼──────────────────┼─────────────────┘
        │                        │ asvas:jobs / asvas:control
 ════════════════════════ TRUST BOUNDARY ═════════════════════════════
 ┌──────────────── EXECUTION PLANE (Go, execution-plane/) ───────────┐
 │ asvas-executor: consumes jobs, strict decode, embedded OPA re-eval │
 │   approval-token verify, DNS resolve+pin, budget/timeouts          │
 │   └─ per-job sandbox child (dev backend: setuid slot UID,          │
 │      no_new_privs, rlimits, pgid kill) + nftables per-UID egress   │
 │   publishes results → asvas:results ; heartbeats → asvas:workers   │
 └───────────────────────────────────────────────────────────────────┘
                                │ only to pinned, policy-approved IP:port
                         Local test target (test-target/)
```

## Key design decisions

1. **Proposal vs authorization.** Model output is a `PlanProposal` (tool id + typed params + rationale). It
   never authorizes anything. Authorization = deterministic validator (scope, schema, budgets, dedupe,
   depth) → OPA decision in the control plane → independent OPA decision in the executor → (if required)
   bound human approval verified by the executor via HMAC token. Any layer can deny; none can override
   another's deny.
2. **Two independent policy evaluations.** The same Rego bundle (`policies/`) is evaluated by the OPA
   server before dispatch and by the Go executor (embedded OPA library, `go:embed`) before execution. A
   compromised/buggy control plane cannot get an out-of-scope job executed, because the executor checks
   the job against the *scope document signed by the control plane at assessment start*, and resolves DNS
   itself.
3. **Scope is a signed, immutable document.** When an assessment starts, its scope + testing policy are
   frozen, canonicalised and HMAC-signed (`scope_sig`). Jobs carry the scope; the executor verifies the
   signature and rejects jobs whose target is outside it.
4. **State machines in Postgres are the source of truth.** LangGraph drives the planning flow and checkpoints
   to Postgres; the assessment/job lifecycle is a separate explicit transition table so recovery never
   depends on in-memory state.
5. **Untrusted content is data.** Target responses enter evidence verbatim (hashed), enter the planner only
   as truncated, JSON-escaped values in a `observations` data field, and can never change scope, policy,
   or tool selection outside the allowlist.
6. **Execution backend interface.** `Sandbox` interface in Go with `devprocess` implementation (approved
   substitute) and a `firecracker` placeholder that refuses to start (returns `ErrBackendUnavailable`).
   Worker status reports the backend name and isolation level so the UI never implies microVM isolation.
7. **Graph store seam.** Assets/relations are in Postgres behind `GraphStore`; Neo4j adapter is M2. Qdrant
   memory is M3. This is sequencing, not removal.

## Assessment state machine

```
DRAFT ─start→ PLANNING ─plan ok→ RUNNING ⇄ AWAITING_APPROVAL
  │              │                 │  └─ all jobs terminal → REPORTING → COMPLETED
  │              └─plan invalid→ FAILED
  └─(any non-terminal) ─cancel→ CANCELLING → CANCELLED ;  ─error/budget→ FAILED
```

## Job state machine

```
PROPOSED → DENIED (policy) | AWAITING_APPROVAL → APPROVED → QUEUED → RUNNING → SUCCEEDED | FAILED | TIMED_OUT
QUEUED/RUNNING → CANCELLED ; FAILED/TIMED_OUT → QUEUED (bounded re-dispatch, attempt+1)
```

## Wire contract (M3)

All control <-> execution messages are protobuf (`proto/asvasrpc/execution/v1/execution.proto`, generated code in
`control-plane/asvasrpc/` and `execution-plane/gen/`, regenerate with `scripts/gen-proto.sh`). Payloads are signed
with HMAC-SHA256 over the exact serialized bytes; receivers reject unknown fields. Each executor also serves
`ExecutorService` (GetStatus, Control) over gRPC with mutual TLS 1.3; the client certificate must carry the URI SAN
`spiffe://asvas.local/control-plane`. Control messages sent over gRPC carry the same HMAC as the stream copy.

## Streams

| Stream | Producer | Consumer group | Payload |
|---|---|---|---|
| `asvas:jobs` | orchestrator | `executors` | `envelope_pb` (base64 JobEnvelope) + `sig` |
| `asvas:results` | executor | `orchestrator` | `result_pb` (base64 JobResult) + `sig` |
| `asvas:control` | API | executor (fan-out by `XREAD`); also sent directly via gRPC | `control_pb` (ControlMessage) + `sig` |
| `asvas:workers` (hash) | executor | API | heartbeat, backend, isolation level, egress mode |

## Directory layout

```
control-plane/   Python (uv) – asvas package, alembic migrations, tests
execution-plane/ Go – cmd/asvas-executor, internal/{policy,netguard,sandbox,checks,stream}
policies/        Rego bundle + opa tests (shared by both planes)
test-target/     Local deliberately-misconfigured HTTP target with known expected outcomes
dashboard/       React + Vite + TypeScript
scripts/         dev start/stop, e2e
docs/            requirements, architecture, threat model, plan, progress, demo
```

## Planning sub-agents (PL-10)
Each planning round runs `agent_discovery` (RECON tools) then `agent_config_verifier` (CONFIG_VERIFIER tools) as LangGraph
nodes, merges their proposals and validates them deterministically. An agent only sees, and may only use, the tools of its
role. The model provider is shared; the agent's name and brief are passed in the request.
