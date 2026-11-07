# ASVAS Threat Model (STRIDE, Milestone 1)

Spec basis: risk registers pp. 32-33, 61-62, 78-80. Scope: the M1 code in this repository running on a
single development host. Assets: assessment scope, target systems, evidence, approvals, audit ledger,
tenant data, model API keys.

## Trust boundaries

1. Browser ↔ API (JWT bearer).
2. API/orchestrator ↔ Postgres/Redis/OPA (localhost, credentials from env).
3. Control plane ↔ execution plane (Redis Streams; HMAC-signed scope and approval tokens).
4. Executor ↔ sandbox child (stdin/stdout JSON, separate UID).
5. Sandbox ↔ target (network, untrusted responses).
6. Control plane ↔ external model provider (redacted prompts).

## Threats and controls

| ID | STRIDE | Threat | Control in M1 | Residual / open |
|---|---|---|---|---|
| T1 | Tampering / EoP | Prompt injection in target banner/body tries to add targets or tools (spec R-03/SR-303) | Observations passed as data only; `PlanProposal` schema; tool allowlist; scope check; OPA x2; tests `test_prompt_injection_*` | Model may still produce *useless* in-scope plans; bounded by budgets |
| T2 | EoP | Out-of-scope egress (SSRF-like) via hostname, redirect, DNS rebinding | Resolve once + validate every IP; pinned dialer; redirects re-validated; nftables per-UID allow-set; deny metadata/link-local/control-plane ports | If nft unavailable executor runs in `app-only` egress mode and reports it |
| T3 | EoP | Sandbox escape (spec R-01/TR-101) | Dev backend: non-root UID, empty caps, `no_new_privs`, rlimits, pgid kill | **Not equivalent to Firecracker/eBPF.** Kernel exploits not mitigated. Firecracker open (Needs infra) |
| T4 | Spoofing | Forged job injected into Redis, or rogue client on the executor's gRPC port | HMAC over serialized protobuf bytes, unknown-field rejection, approval tokens; gRPC requires mutual TLS 1.3 and the control-plane SPIFFE identity, and control messages are HMAC-signed as well | Shared HMAC key; dev CA without rotation; Redis not yet TLS |
| T5 | Repudiation | Actions without trace | Hash-chained `audit_events`, UPDATE/DELETE blocked by trigger; every transition, policy decision, tool call, approval, failure recorded | DB superuser can still drop trigger → WORM export M3 |
| T6 | Info disclosure | Cross-tenant data access (R-04/TR-404) | RLS with `FORCE`, app role not owner, tenant set per transaction; test | |
| T7 | Info disclosure | Secrets/evidence sent to external model | `redact()` before provider call; deterministic provider default; keys server-side only | Regex redaction is best-effort |
| T8 | DoS | Target exhaustion (R-05/OR-404) | GET/HEAD/OPTIONS only, request budget, req/s cap, timeouts, concurrency limit | |
| T9 | DoS | Planner loop (R-02/AR-202) | Depth cap ≤15, fingerprint dedupe, Tarjan SCC, replanning cap, token & time budgets | |
| T10 | EoP | Approval replay / parameter swap | Approval bound to sha256(assessment, job, tool, params, target) + expiry; executor re-verifies HMAC; approver ≠ requester | |
| T11 | Tampering | Duplicate job delivery causes double execution or double findings | Redis `SETNX` claim per (job, attempt); result ingestion idempotent on (job, attempt); unique constraints | |
| T12 | DoS | Hung worker | Per-job deadline enforced in executor (kill pgid) and control plane reaper (TIMED_OUT) | |
| T13 | EoP | Dev login / weak JWT secret used in prod | Dev login only when `ASVAS_ENV=development`; startup refuses default secrets outside development | |
| T14 | Info disclosure | Log/evidence injection into UI | React escapes text; evidence rendered as text only | |
| T15 | Tampering | Supply chain | Lockfiles committed; CI installs with frozen lockfiles | No SBOM/signing yet |
