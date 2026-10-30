# ASVAS Requirements Register

Source: *Autonomous AI Security Validation System – Google Gemini.pdf* (90 pages, exported 19/07/2026).
Page numbers below are PDF page numbers. The PDF is treated as the **specification of intent**, not as proof
that its numbers, code samples, or citations are correct (see "Spec issues" at the end).

Status legend:

| Status | Meaning |
|---|---|
| **Done (M1)** | Implemented in milestone 1 and covered by an automated test |
| **Partial (M1)** | Some of the requirement implemented; remaining gap stated |
| **Dev substitute** | Implemented with an approved development substitute that is *not* equivalent; real requirement stays open |
| **Planned (Mx)** | Not implemented; sequenced to milestone x (see implementation-plan.md) |
| **Needs infra** | Cannot be built/verified without infrastructure not available here (KVM, cloud, IdP) |
| **Aspirational** | Business/metric target; not a code requirement; will not be claimed |

## 1. Scope, safety boundaries, exclusions

| ID | Requirement | Pages | Status | Notes / evidence |
|---|---|---|---|---|
| SC-01 | Only non-destructive discovery, configuration analysis, bounded validation in explicitly designated environments | 46-47 | Done (M1) | Tool registry contains only non-destructive checks; `DESTRUCTIVE` risk category denied by Rego with no override path in M1 |
| SC-02 | Exclusion: no raw exploit strings outside schema filters; no unguided payload generation | 13-14, 47 | Done (M1) | Model output can only select allowlisted tool IDs + schema-validated params; no free-text payloads |
| SC-03 | Exclusion: no destructive testing / flooding / data modification | 47 | Done (M1) | GET/HEAD/OPTIONS only; request budget + rate limit enforced in executor |
| SC-04 | Exclusion: no cross-boundary traffic outside defined namespace | 47, 48 | Done (M1) | Scope check in control plane, Rego in OPA, Rego re-evaluated in Go executor, pinned-IP dialing, nftables per-UID egress |
| SC-05 | No automated modification of live production without human sign-off | 47 | Done (M1) | No production-changing tool exists; `production_change` risk category requires approval and is denied by default |
| SC-06 | Out-of-scope request must trigger shutdown/lock of active execution context | 47 | Partial (M1) | Out-of-scope dispatch attempt → job denied, assessment moved to `FAILED` with `scope_violation`; global lock = emergency stop (manual). Automatic global lock planned M2 |
| SC-07 | Scope cannot be expanded dynamically by the reasoning core | 48 | Done (M1) | Scope is immutable once assessment leaves DRAFT; planner proposals outside scope are rejected and audited |
| SC-08 | Pre-run network isolation check; halt if fails | 53 | Partial (M1) | Executor self-test of egress enforcement at start-up, reported in worker status; per-run check planned M2 |

## 2. Control plane, API, identity

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| CP-01 | Modular monolith control plane with strict internal interfaces (`api`, `planning`, `reporting`, `tools`) | 66-68 | Done (M1) | `control-plane/asvas/*` modules |
| CP-02 | FastAPI, Python 3.11+ | 6, 24, 81 | Done (M1) | Python ≥3.11 (CI on 3.12/3.13) |
| CP-03 | Versioned REST `/api/v1`, async jobs return 202 + status URL | 86-87 | Done (M1) | `POST /api/v1/assessments/{id}/start` → 202 |
| CP-04 | RFC 9457 problem-details errors | 87 | Done (M1) | `application/problem+json` handler |
| CP-05 | Strict schema validation of all inputs (`extra=forbid`) | 87, 76 | Done (M1) | Pydantic v2 models, `extra="forbid"` |
| CP-06 | Rate limiting 100 req/min per tenant (Redis token bucket) | 7, 86-87 | Partial (M1) | Fixed-window Redis limiter per tenant; token bucket planned |
| CP-07 | OAuth2/JWT auth; enterprise SSO via OIDC; MFA | 32, 48-49, 86 | Partial (M1) | HS256 JWT with roles+tenant; dev login (disabled outside `ASVAS_ENV=development`). OIDC/MFA: Planned M3 (Needs IdP) |
| CP-08 | Role-based access (RACI: admin/CISO, red-team lead approver, operator, viewer) | 40-42 | Done (M1) | `viewer`, `operator`, `approver`, `admin`; enforced per endpoint, tested |
| CP-09 | No single user can bypass HITL / alter global parameters alone | 41 | Done (M1) | Approver ≠ requester enforced; emergency stop is admin-only and audited |
| CP-10 | mTLS between control & execution planes; TLS 1.3 everywhere; Vault CA | 58, 66, 68 | Planned (M3) | M1 runs on localhost with Redis password; not claimed |
| CP-11 | Envelope/AES-256 encryption at rest; KMS | 7, 15, 24, 85 | Planned (M3) | Not implemented. Evidence stored plaintext in Postgres in M1 (documented limitation) |

## 3. Planning & orchestration

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| PL-01 | LangGraph explicit nodes / conditional edges; no open-ended LLM loops | 2, 9-10, 64-66, 71-72 | Done (M1) | `planning/graph.py`; graph is a fixed DAG with bounded replanning |
| PL-02 | Typed state + validated transitions | 64-65, 72 | Done (M1) | Assessment & job state machines with transition tables; illegal transitions raise and are audited |
| PL-03 | Durable checkpoints | 4, 65, 72 | Done (M1) | LangGraph `PostgresSaver`; assessment/job state durable in Postgres |
| PL-04 | Max depth D_max = 15; loop detection within 2 runs; Tarjan SCC | 9, 49, 72 | Done (M1) | Depth cap configurable (≤15); duplicate (tool,target,params) fingerprint rejection; Tarjan SCC check on plan graph |
| PL-05 | Failed node → fallback to prior state; 3 consecutive failures mark path blocked | 49, 69 | Partial (M1) | Bounded retries (max attempts) then job `FAILED` + branch blocked; prior-state rollback for graph planning = checkpoint resume |
| PL-06 | Structured model output validated with Pydantic; temperature 0 | 9, 70 | Done (M1) | `PlanProposal` schema; providers forced to JSON + validation; invalid → honest `PLANNING_FAILED` |
| PL-07 | Provider abstraction, vendor independence, fallback provider | 25-26, 56-57 | Partial (M1) | `ModelProvider` interface, `deterministic-test` + `anthropic` providers; circuit breaker/fallback chain Planned M2 |
| PL-08 | MCP as model integration protocol | 25-27 | Planned (M3) | Not implemented; provider interface keeps the seam |
| PL-09 | Per-assessment token & time budgets; < $0.50/step; model timeout < 10 s | 22-23, 26, 54 | Partial (M1) | Token budget, wall-clock budget, 10 s model timeout enforced; $ cost not computed |
| PL-10 | Specialized sub-agents (Recon/Analysis/Validation), restricted tool sub-schemas | 2, 68-70 | Partial (M1) | Tool registry tags each tool with an agent role; only Recon/Config roles have tools in M1 |
| PL-11 | GoT / POMDP reward-based branch selection | 8-9, 70-71 | Planned (M4) | Mathematical framing not implemented; deterministic planner orders by registry priority |
| PL-12 | Redis Streams event bus between modules | 23, 66-67, 81 | Done (M1) | `asvas:jobs`, `asvas:results`, `asvas:control` streams with consumer groups |
| PL-13 | Idempotent jobs, recovery after worker failure | (user req.) 14, 51 | Done (M1) | Idempotency keys, `XAUTOCLAIM` of stale entries, reaper for overdue jobs, bounded re-dispatch |

## 4. Policy, tool mediation, execution

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| PO-01 | OPA/Rego evaluated before execution, default deny | 3-4, 27, 75 | Done (M1) | `policies/asvas/*.rego`; control plane queries OPA server; executor re-evaluates the same bundle via embedded OPA (independent) |
| PO-02 | Risk tiers Low (auto) / Medium (pre-flight OPA) / High (HITL cryptographic sign-off) | 4 | Done (M1) | Risk tier per tool; per-assessment policy may also require approval for medium |
| PO-03 | Approval bound to assessment, action, params, expiry; no reuse after change | (user req.) 4, 32 | Done (M1) | Binding hash + HMAC approval token verified by executor; tested |
| PO-04 | "Cryptographic" admin sign-off via web | 4, 32 | Partial (M1) | Server-side HMAC-signed approval token; per-user asymmetric signatures (WebAuthn) Planned M3 |
| PO-05 | Tool Abstraction Layer: strongly typed schemas, `additionalProperties:false`, no shell | 2-3, 27-28, 74-76 | Done (M1) | Pydantic (control plane) + strict Go decoding (executor); no shell tool exists |
| PO-06 | gRPC/Protobuf interface to workers | 6, 27, 31 | Planned (M2) | M1 transports schema-validated JSON over Redis Streams; protobuf contract planned |
| PO-07 | Go execution proxy | 6, 23-24, 63, 75 | Done (M1) | `execution-plane/` (Go 1.26) |
| PO-08 | Rate limit ≤1000 (policy), ≤500 pkt/s discovery | 3, 11 | Done (M1) | Executor request budget + per-job req/s cap; policy caps |
| PO-09 | Tool timeout 300 s per call; validation < 30 s | 6, 14, 75 | Done (M1) | Per-tool timeout ≤ 30 s for HTTP checks, hard max 300 s |
| PO-10 | Firecracker microVMs, read-only rootfs, snapshots < 850 ms | 2, 6, 30-31, 63-64 | Dev substitute | **Approved dev substitute**: per-job child process, setuid to per-slot UID, `no_new_privs`, rlimits, process-group kill. Not equivalent. Firecracker: Needs infra (KVM) |
| PO-11 | Drop CAP_SYS_ADMIN/NET_ADMIN/SYS_RAWIO/CHOWN | 64 | Done (M1) | Child runs as non-root UID with empty capability sets + `no_new_privs` (verified by test reading `/proc/self/status`) |
| PO-12 | eBPF syscall monitor, SIGKILL < 50 ms | 3, 30-31, 64, 76 | Needs infra | Not implemented; requires eBPF-capable host & tooling. Tracked M3 |
| PO-13 | Egress restricted to approved targets (default-deny) | 3, 48, 75, 80, 89 | Done (M1) | nftables per-UID allow-set + app-level pinned dialing; falls back to app-only and reports degraded status if nft unavailable |
| PO-14 | DNS rebinding & redirect validation | (user req.) 9, 47 | Done (M1) | Resolve-once, validate all A/AAAA, pin; each redirect re-validated; tested |
| PO-15 | Emergency stop kills active workers | (user req.) 62-63 | Done (M1) | Admin endpoint → Redis control message + flag; executor kills process groups; tested |
| PO-16 | Unique short-lived per-sandbox credentials | 7 | Planned (M3) | N/A for local dev |

## 5. Data, evidence, findings, reporting

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| DA-01 | PostgreSQL 16 durable state; migrations | 24, 84-85 | Done (M1) | Alembic migrations |
| DA-02 | Tenant isolation via RLS with `app.current_tenant_id` | 32, 79, 84-85 | Done (M1) | `FORCE ROW LEVEL SECURITY`, app runs as non-owner role; cross-tenant test |
| DA-03 | Neo4j asset topology graph | 10, 24, 84 | Planned (M2) | M1 stores assets/relations in Postgres behind `GraphStore` interface; Neo4j adapter M2 |
| DA-04 | Qdrant long-term memory with tenant filter + anonymization | 16-17, 73-74 | Planned (M3) | Redaction pipeline exists (M1) and is reused |
| DA-05 | Redis short-term memory, erased after run | 16, 73 | Partial (M1) | Per-assessment Redis keys deleted on terminal state |
| DA-06 | Evidence SHA-256, append-only, linked to findings | 15, 77, 84-85 | Done (M1) | `evidence` table, hash verified on read, UPDATE/DELETE blocked by trigger |
| DA-07 | Findings: asset, check id, timestamp, assessment, evidence refs, observed behaviour, severity rationale, confidence, verification status, remediation, retest history | (user req.) 12-13 | Done (M1) | `findings` + `finding_retests` tables |
| DA-08 | Suspected vs verified; no confirmation from banners/model confidence | (user req.) 12 | Done (M1) | Banner-derived observations are `suspected` only; tested |
| DA-09 | CVSS 4.0 + CWE mapping, deterministic | 12-13 | Partial (M1) | CWE mapped deterministically; severity from fixed rule table with rationale; CVSS 4.0 vector calc Planned M2 |
| DA-10 | Append-only, hash-chained audit ledger (WORM) | 6, 14, 42, 58, 63 | Partial (M1) | Hash-chained `audit_events`, UPDATE/DELETE blocked; external WORM storage Planned M3 |
| DA-11 | Reports JSON/Markdown/PDF, via separate worker | 15-16 | Partial (M1) | JSON + Markdown generated from DB state; PDF and separate renderer Planned M2 |
| DA-12 | Compliance mapping (NIST 800-53, ISO 27001, SOC2, OWASP) | 15, 59-61 | Planned (M4) | Not claimed |
| DA-13 | Redact secrets before external model; untrusted output treated as data | 22, 26, 55, 74, 78, 80 | Done (M1) | `redaction.py`; target text enters prompts only as escaped, truncated quoted data; tested |
| DA-14 | Retention 30 days for transient logs; partitioning | 77, 85 | Planned (M3) | |
| DA-15 | Bloom-filter dedupe of discovery stream; streaming JSON parse | 10 | Planned (M2) | M1 dedupes by unique constraint |

## 6. Dashboard / HITL UI

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| UI-01 | Responsive React dashboard with real-time execution graph, status, logs | 32, 43 | Done (M1) | Polling (2 s); WebSockets Planned M2 |
| UI-02 | HITL approval queue | 32 | Done (M1) | |
| UI-03 | Persona modes (junior vs advanced views) | 42-44 | Planned (M3) | |
| UI-04 | Read-only auditor dashboard | 60 | Partial (M1) | `viewer` role sees audit log read-only |

## 7. Operations / NFR (not claimed)

| ID | Requirement | Pages | Status |
|---|---|---|---|
| NF-01 | API p95 < 200 ms, 500 tenants, 1000 parallel microVMs, 99.9 % uptime, RTO 15 min, RPO 5 min | 50-51 | Aspirational — not measured |
| NF-02 | Precision ≥ 99 %, FP < 1 %, 80 % alert reduction, < 15 ms/endpoint | 39 | Aspirational — not measured, will not be displayed |
| NF-03 | EKS + bare-metal EC2, Terraform, Helm, Prometheus/Grafana, OpenTelemetry | 1, 32-33, 51, 83, 88-89 | Planned (M4); no paid infra will be provisioned automatically |
| NF-04 | Hash-pinned dependencies, image scanning in CI | 30, 79, 82 | Partial (M1) | `uv.lock`, `go.sum`, `package-lock.json`; image scanning N/A (no images yet) |
| NF-05 | STRIDE threat model | 30 | Done (M1) | `docs/threat-model.md` |

---

## Spec issues found (contradictions, unsupported claims, outdated items)

| # | Issue | Pages | Resolution |
|---|---|---|---|
| I-1 | Document labels itself "2.0.0-PROD", "enterprise-ready", "production-ready" while being a planning draft; several sections are truncated or interleaved with chat UI text ("You stopped this response") | 5, 34, 66 | Treated as draft spec; no readiness claims made |
| I-2 | Go sample uses `SysProcAttr.NoNewPrivs` — this field does not exist in Go's `syscall` package on Linux; it also combines `CLONE_NEWNET` (no network) with a network scanning tool | 64 | `no_new_privs` set via `prctl` in the re-exec'd child; network namespace not used for HTTP checks (egress controlled by nftables) |
| I-3 | LangGraph sample is syntactically broken (unclosed dict, `"verification": "end"` routes to a missing node), and node returns key `next_action` absent from state | 65-66 | Rewritten; not copied |
| I-4 | Rego sample uses pre-1.0 syntax (`allow { … }` without `if`), invalid under OPA 1.x defaults | 3-4 | Policies written in OPA v1 syntax |
| I-5 | Hard-coded scope CIDR `10.100.0.0/16` in policy | 4 | Scope comes from assessment data, never from policy text |
| I-6 | Discovery schema: `target_range` with `format: ipv4` (a range is not an address); `rate_limit` minimum 100 forces ≥100 req/s | 3 | Separate `target` (host/IP) field; rate limit 1–10 req/s for HTTP checks |
| I-7 | Medium risk includes "credential stuffing checks" labelled autonomous — conflicts with non-destructive/lockout guidance | 4, 11 | Not implemented; would be High risk + approval |
| I-8 | Metrics (precision ≥ 99 %, < 15 ms/endpoint, < 45 ms sync, < 850 ms spin-up, 50 ms eBPF kill) are unsupported targets | 6, 30, 39, 51 | Not displayed or claimed |
| I-9 | "Go 1.22+", "Python 3.11" — outdated; current OPA (v1.21+) and go-redis v9.23 require Go ≥ 1.26 | 6, 23, 81 | Go 1.26 toolchain, Python ≥ 3.11 |
| I-10 | References with doubtful/unverifiable titles (e.g., "IEEE Std 830-2024", "OWASP Top 10 Automated Attack Surface Mapping Framework (2025)", Besta et al. dated 2024 with misspelt title) | 10, 50, 71 | Not relied upon |
| I-11 | Firecracker said to need "nested virtualization" on `i3en.metal`; bare metal provides KVM directly, nested virt not needed | 88 | Noted |
| I-12 | "Sandbox via microVMs **or** restricted Docker" (p2–3) vs. Docker explicitly rejected (p75, 82) | 2-3, 75, 82 | Firecracker remains the target; dev substitute explicitly labelled |
| I-13 | Sanitizer sample `re.sub(r'[^\w\s\.\:\/\-\=]','',…)` is not a prompt-injection defense (natural-language injections pass) | 80 | Structural separation (data never in instruction channel) + output validation, not character stripping |
| I-14 | Evidence DDL stores `payload_raw_stream TEXT` alongside "encrypted" claims; RLS via `current_setting` bypassed by superuser/owner unless `FORCE` | 85 | `FORCE ROW LEVEL SECURITY`, non-owner app role; encryption tracked as open |
| I-15 | "Temperature 0.0" assumed to give determinism; it does not guarantee identical outputs | 9, 70 | Determinism comes from validation, not temperature |
