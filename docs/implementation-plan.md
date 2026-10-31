# Implementation Plan

Spec roadmap (pp. 29-32) orders work: containment → state → tool proxies → LangGraph → HITL/UI → hardening.
This plan keeps that order for *safety controls* but delivers a thin end-to-end slice first so every later
milestone is tested against a running system. Sequencing is not removal: every requirement in
`requirements.md` has a milestone.

## M1 — First runnable vertical slice (this milestone)

1. Repo, docs, CI skeleton.
2. Postgres schema + Alembic migrations (tenants, users, assessments, jobs, approvals, evidence,
   findings, retests, assets, audit) with RLS.
3. API: dev auth (JWT, roles), assessments CRUD + scope/policy validation, start/cancel/retest,
   approvals, findings, evidence, audit, workers, emergency stop, reports.
4. Policy: Rego bundle + `opa test`; OPA server client; embedded OPA in executor.
5. Planning: LangGraph graph (propose → validate → policy → route), deterministic test provider,
   Anthropic provider (untested live), Postgres checkpointer, budgets.
6. Orchestrator: Redis Streams dispatcher, result ingester, reaper, approvals binding.
7. Executor (Go): strict decode, scope signature, OPA, DNS pin, redirect check, dev sandbox, nftables,
   cancellation, heartbeats.
8. Checks: `http.security_headers` (low), `http.allowed_methods` (medium, OPTIONS only).
9. Local test target with known expected outcomes.
10. Dashboard.
11. Tests: unit + integration + e2e; CI workflow.

## M2 — Correlation and depth (status: see progress.md; gRPC contract moved to M3)
- Neo4j `GraphStore` adapter (DA-03); asset correlation across checks.
- gRPC/protobuf execution contract (PO-06); token-bucket rate limiter (CP-06).
- Provider circuit breaker + fallback chain (PL-07); CVSS 4.0 calculator (DA-09).
- WebSocket status stream (UI-01); PDF reports via separate renderer worker (DA-11).
- TLS check tool (low risk); automatic global lock on scope violation (SC-06); per-run isolation check (SC-08).

## M3 — Hardening (needs infrastructure decisions)
- Firecracker backend on a KVM host (PO-10) + eBPF monitor (PO-12) — requires a KVM-capable machine.
- OIDC SSO + MFA (CP-07), WebAuthn approvals (PO-04), mTLS/Vault (CP-10), envelope encryption/KMS (CP-11).
- Qdrant memory with anonymization (DA-04); WORM audit export (DA-10); retention jobs (DA-14); MCP (PL-08).

## M4 — Scale / enterprise (no automatic paid provisioning)
- Terraform/Helm/EKS manifests, Prometheus/OTel (NF-03); compliance mapping (DA-12); GoT/POMDP scoring (PL-11);
  persona UI modes (UI-03); load testing before any NFR claim (NF-01/02).

## Dependencies
- M3 Firecracker blocks any claim of hardware isolation.
- Neo4j adapter (M2) precedes multi-stage path analysis.
- OIDC (M3) precedes any multi-user deployment outside a dev host.
