# ASVAS Requirements Register

Source: *Autonomous AI Security Validation System – Google Gemini.pdf* (90 pages, exported 19/07/2026).
Page numbers below are PDF page numbers. The PDF is treated as the **specification of intent**, not as proof
that its numbers, code samples, or citations are correct (see "Spec issues" at the end).

Status legend:

| Status | Meaning |
|---|---|
| **Done** / **Done (M2)** | Implemented (milestone 1, or milestone 2 where marked) and covered by an automated test |
| **Partial** | Some of the requirement implemented; remaining gap stated |
| **Dev substitute** | Implemented with an approved development substitute that is *not* equivalent; real requirement stays open |
| **Planned (Mx)** | Not implemented; sequenced to milestone x (see implementation-plan.md) |
| **Needs infra** | Cannot be built/verified without infrastructure not available here (KVM, cloud, IdP) |
| **Aspirational** | Business/metric target; not a code requirement; will not be claimed |

## 1. Scope, safety boundaries, exclusions

| ID | Requirement | Pages | Status | Notes / evidence |
|---|---|---|---|---|
| SC-01 | Only non-destructive discovery, configuration analysis, bounded validation in explicitly designated environments | 46-47 | Done | Tool registry contains only non-destructive checks; `DESTRUCTIVE` risk category denied by Rego with no override path in M1 |
| SC-02 | Exclusion: no raw exploit strings outside schema filters; no unguided payload generation | 13-14, 47 | Done | Model output can only select allowlisted tool IDs + schema-validated params; no free-text payloads |
| SC-03 | Exclusion: no destructive testing / flooding / data modification | 47 | Done | GET/HEAD/OPTIONS only; request budget + rate limit enforced in executor |
| SC-04 | Exclusion: no cross-boundary traffic outside defined namespace | 47, 48 | Done | Scope check in control plane, Rego in OPA, Rego re-evaluated in Go executor, pinned-IP dialing, nftables per-UID egress |
| SC-05 | No automated modification of live production without human sign-off | 47 | Done | No production-changing tool exists; `production_change` risk category requires approval and is denied by default |
| SC-06 | Out-of-scope request must trigger shutdown/lock of active execution context | 47 | Done (M2) | Executor scope denial of a control-plane-approved job → assessment FAILED + halt key + `scope_violation.lockdown` audit; tenant-wide lock = emergency stop |
| SC-07 | Scope cannot be expanded dynamically by the reasoning core | 48 | Done | Scope is immutable once assessment leaves DRAFT; planner proposals outside scope are rejected and audited |
| SC-08 | Pre-run network isolation check; halt if fails | 53 | Done (M2) | Executor egress self-test at start-up; per-assessment `require_kernel_egress` policy makes every job require proven nftables enforcement (Rego, execution plane) |

## 2. Control plane, API, identity

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| CP-01 | Modular monolith control plane with strict internal interfaces (`api`, `planning`, `reporting`, `tools`) | 66-68 | Done | `control-plane/asvas/*` modules |
| CP-02 | FastAPI, Python 3.11+ | 6, 24, 81 | Done | Python ≥3.11 (CI on 3.12/3.13) |
| CP-03 | Versioned REST `/api/v1`, async jobs return 202 + status URL | 86-87 | Done | `POST /api/v1/assessments/{id}/start` → 202 |
| CP-04 | RFC 9457 problem-details errors | 87 | Done | `application/problem+json` handler |
| CP-05 | Strict schema validation of all inputs (`extra=forbid`) | 87, 76 | Done | Pydantic v2 models, `extra="forbid"` |
| CP-06 | Rate limiting 100 req/min per tenant (Redis token bucket) | 7, 86-87 | Done (M2) | Atomic Redis Lua token bucket per tenant, `Retry-After` header |
| CP-07 | OAuth2/JWT auth; enterprise SSO via OIDC; MFA | 40-42, 86 | Done (M4, dev IdP) | OIDC authorization code + PKCE (S256) from the dashboard to Keycloak 26.4.2 (`scripts/keycloak-dev.sh`, TLS 1.3); API verifies RS256 tokens via JWKS (issuer, audience `asvas-api`, client, verified e-mail), requires `amr` ∋ `otp` (TOTP is a required action for every user; first enrolment-only token is refused and a fresh login with a code is forced), and the IdP realm role `asvas-<role>` must match the ASVAS user role. Dev HS256 login only in development, refused in production; production config refuses to start without an issuer or with MFA off. Tests `test_oidc.py` (17) + Playwright e2e `dashboard/e2e/oidc-sso.e2e.cjs` against live Keycloak (enrolment and returning-user paths). Open: Keycloak runs in dev mode (H2); no refresh-token handling (re-login after 10 min token expiry); WebAuthn not configured |
| CP-08 | Role-based access (RACI: admin/CISO, red-team lead approver, operator, viewer) | 40-42 | Done | `viewer`, `operator`, `approver`, `admin`; enforced per endpoint, tested |
| CP-09 | No single user can bypass HITL / alter global parameters alone | 41 | Done | Approver ≠ requester enforced; emergency stop is admin-only and audited |
| CP-10 | mTLS between control & execution planes; TLS 1.3 everywhere; Vault CA | 58, 66, 68 | Partial (M3) | Executor gRPC requires mutual TLS 1.3 + SPIFFE-URI client identity (dev CA via `scripts/dev-certs.sh`); dev stack (`scripts/dev-tls-services.sh`): PostgreSQL requires TLS 1.3 (`hostnossl` rejected, clients `sslmode=verify-full`), Redis TLS 1.3-only on :6380 (`rediss://`, plaintext port disabled; production refuses `redis://`), OPA HTTPS TLS 1.3, API HTTPS (uvicorn, TLS 1.2+ — not pinned to 1.3); tests `test_service_tls.py`. Open: Neo4j bolt TLS, Vault CA, automated rotation |
| CP-11 | Envelope/AES-256 encryption at rest; KMS | 7, 15, 24, 85 | Partial (M3) | Evidence and rendered reports sealed with AES-256-GCM envelope encryption (per-object DEK, KEK from key ring, record-bound AAD); rotation + DEK re-wrap (`asvas keys rotate|rewrap|status`); evidence content stays immutable. Open: real KMS/Vault instead of the local key file, DB volume encryption, rows written before M3 remain plaintext (reported by `keys status`) |

## 3. Planning & orchestration

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| PL-01 | LangGraph explicit nodes / conditional edges; no open-ended LLM loops | 2, 9-10, 64-66, 71-72 | Done | `planning/graph.py`; graph is a fixed DAG with bounded replanning |
| PL-02 | Typed state + validated transitions | 64-65, 72 | Done | Assessment & job state machines with transition tables; illegal transitions raise and are audited |
| PL-03 | Durable checkpoints | 4, 65, 72 | Done | LangGraph `PostgresSaver` (thread = assessment:round); assessment/job state durable in Postgres; lost planning requests re-issued by reaper |
| PL-04 | Max depth D_max = 15; loop detection within 2 runs; Tarjan SCC | 9, 49, 72 | Done | Depth cap configurable (≤15); duplicate (tool,target,params) fingerprint rejection; Tarjan SCC check on plan graph |
| PL-05 | Failed node → fallback to prior state; 3 consecutive failures mark path blocked | 49, 69 | Partial (M3) | Consecutive failures counted per path (tool × service) in short-term memory; at 3 the path is blocked: no retry, audited `plan.path_blocked`, validator rejects re-proposals; success resets. Prior-state fallback = LangGraph checkpoint resume (per-round thread). Tests `test_planning_controls.py`. Open: blocked set lives in Redis only (lost if Redis is flushed mid-run) |
| PL-06 | Structured model output validated with Pydantic; temperature 0 | 9, 70 | Done | `PlanProposal` schema; providers forced to JSON + validation; invalid → honest `PLANNING_FAILED` |
| PL-07 | Provider abstraction, vendor independence, fallback provider | 25-26, 56-57 | Done (M2) | `ModelProvider` interface; circuit breaker (3 failures → 60 s open); optional explicit fallback to the deterministic planner, recorded as not-AI. Second live vendor not added |
| PL-08 | MCP as model integration protocol | 25-27 | Planned (M3) | Not implemented; provider interface keeps the seam |
| PL-09 | Per-assessment token & time budgets; < $0.50/step; model timeout < 10 s | 22-23, 26, 54 | Done (M3) | Token, wall-clock and cost budgets (`max_cost_usd_cents`, `cost_usd_micros` per assessment); per-step ceiling ≤ $0.50 (config cannot exceed): `max_tokens` capped so worst case (1 token/byte input) stays under it, actual cost re-checked; live provider refuses to run without configured prices (no guessed prices); 10 s timeout. Tests `test_planning_controls.py` |
| PL-10 | Specialized sub-agents (Recon/Analysis/Validation), restricted tool sub-schemas | 2, 68-70 | Partial (M3) | Planning graph runs sub-agents in sequence (`agent_discovery` → `agent_config_verifier` → merge → validate); each sees only tools of its role and its steps are rejected if they name a tool outside its sub-schema; agent recorded per plan node and in `planning.round` audit. Tests `test_agents.py`. Open: Identity Analyst / validation agents have no tools yet; all agents share one model provider |
| PL-11 | GoT / POMDP reward-based branch selection | 8-9, 70-71 | Planned (M4) | Mathematical framing not implemented; deterministic planner orders by registry priority |
| PL-12 | Redis Streams event bus between modules | 23, 66-67, 81 | Done | `asvas:jobs`, `asvas:results`, `asvas:control` streams with consumer groups |
| PL-13 | Idempotent jobs, recovery after worker failure | (user req.) 14, 51 | Done | Idempotency keys, `XAUTOCLAIM` of stale entries, reaper for overdue jobs, bounded re-dispatch |

## 4. Policy, tool mediation, execution

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| PO-01 | OPA/Rego evaluated before execution, default deny | 3-4, 27, 75 | Done | `policies/asvas/*.rego`; control plane queries OPA server; executor re-evaluates the same bundle via embedded OPA (independent) |
| PO-02 | Risk tiers Low (auto) / Medium (pre-flight OPA) / High (HITL cryptographic sign-off) | 4 | Done | Risk tier per tool; per-assessment policy may also require approval for medium |
| PO-03 | Approval bound to assessment, action, params, expiry; no reuse after change | (user req.) 4, 32 | Done | Binding hash + HMAC approval token verified by executor; tested |
| PO-04 | "Cryptographic" admin sign-off via web | 4, 32 | Partial (M3) | Every approve/reject decision must carry the approver's own Ed25519 signature over `asvas-approval-v1|id|decision|binding_hash|expires` (production cannot disable); keys registered/revoked per user (`approver_keys`, RLS), private key non-extractable WebCrypto key in the browser; signature + key fingerprint stored on the approval and in the audit ledger. Tests `test_approver_signatures.py`. Open: WebAuthn/hardware authenticator + attestation; executor does not re-verify the approver signature (relies on control-plane HMAC token) |
| PO-05 | Tool Abstraction Layer: strongly typed schemas, `additionalProperties:false`, no shell | 2-3, 27-28, 74-76 | Done | Pydantic (control plane) + strict Go decoding (executor); no shell tool exists |
| PO-06 | gRPC/Protobuf interface to workers | 6, 27, 31 | Done (M3) | `proto/asvasrpc/execution/v1/execution.proto`: typed JobEnvelope (params oneof), JobResult, ControlMessage over Redis Streams with HMAC over serialized bytes and unknown-field rejection; `ExecutorService` (GetStatus, Control) served by each executor over gRPC |
| PO-07 | Go execution proxy | 6, 23-24, 63, 75 | Done | `execution-plane/` (Go 1.26) |
| PO-08 | Rate limit ≤1000 (policy), ≤500 pkt/s discovery | 3, 11 | Done | Executor request budget + per-job req/s cap; policy caps |
| PO-09 | Tool timeout 300 s per call; validation < 30 s | 6, 14, 75 | Done | Per-tool timeout ≤ 30 s for HTTP checks, hard max 300 s |
| PO-10 | Firecracker microVMs, read-only rootfs, snapshots < 850 ms | 2, 6, 30-31, 63-64 | Dev substitute | **Approved dev substitute**: per-job child process, setuid to per-slot UID, `no_new_privs`, rlimits, process-group kill. Not equivalent. Firecracker: Needs infra (KVM) |
| PO-11 | Drop CAP_SYS_ADMIN/NET_ADMIN/SYS_RAWIO/CHOWN | 64 | Done | Child runs as non-root UID with empty capability sets + `no_new_privs` (verified by test reading `/proc/self/status`) |
| PO-12 | eBPF syscall monitor, SIGKILL < 50 ms | 3, 30-31, 64, 76 | Needs infra | Not implemented; requires eBPF-capable host & tooling. Tracked M3 |
| PO-13 | Egress restricted to approved targets (default-deny) | 3, 48, 75, 80, 89 | Done | nftables per-UID allow-set + app-level pinned dialing; falls back to app-only and reports degraded status if nft unavailable |
| PO-14 | DNS rebinding & redirect validation | (user req.) 9, 47 | Done | Resolve-once, validate all A/AAAA, pin; each redirect re-validated; tested |
| PO-15 | Emergency stop kills active workers | (user req.) 62-63 | Done | Admin endpoint → Redis control message + flag; executor kills process groups; tested |
| PO-17 | TLS configuration validation (spec p.4 'TLS version validation', low risk) | 4 | Done (M2) | `tls.configuration`: ≤2 handshakes (default, TLS1.0/1.1-only); rules TLS-UNTRUSTED/HOSTNAME/EXPIRED/EXPIRING/LEGACY; https-only enforced in Rego |
| PO-16 | Unique short-lived per-sandbox credentials | 7, 414 | Done (M4, scope-adjusted) | Each sandbox run gets a fresh credential derived from a per-process random master (unique even for retries in the same slot, TTL = job timeout + 5 s); the sandbox must MAC its result with it before expiry; the executor rejects results from another run, tampered or late; key wiped after use; credential id + verification in the attestation/audit. Tests `cred_test.go`, worker + E2E assertions. Scope: sandboxes need no cloud/IAM access here, so no cloud credentials are issued (STS-style issuer for that case not implemented) |

## 5. Data, evidence, findings, reporting

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| DA-01 | PostgreSQL 16 durable state; migrations | 24, 84-85 | Done | Alembic migrations |
| DA-02 | Tenant isolation via RLS with `app.current_tenant_id` | 32, 79, 84-85 | Done | `FORCE ROW LEVEL SECURITY`, app runs as non-owner role; cross-tenant test |
| DA-03 | Neo4j asset topology graph | 10, 24, 84 | Done (M2) | Neo4j 5.26 projection of Postgres state (idempotent MERGE, tenant-scoped queries, `asvas graph-resync`); multi-stage path analysis still planned (M4) |
| DA-04 | Qdrant long-term memory with tenant filter + anonymization | 16-17, 73-74 | Planned (M3) | Redaction pipeline exists (M1) and is reused |
| DA-05 | Redis short-term memory, erased after run | 16, 73 | Done (M3) | `asvas:st:<assessment>:*` holds working state (failure counters, blocked paths, per-round notes, planning lock) with TTL = wall-clock budget + 1 h; deleted on terminal state. Tests `test_planning_controls.py` |
| DA-06 | Evidence SHA-256, append-only, linked to findings | 15, 77, 84-85 | Done | `evidence` table, hash verified on read, UPDATE/DELETE blocked by trigger |
| DA-07 | Findings: asset, check id, timestamp, assessment, evidence refs, observed behaviour, severity rationale, confidence, verification status, remediation, retest history | (user req.) 12-13 | Done | `findings` + `finding_retests` tables |
| DA-08 | Suspected vs verified; no confirmation from banners/model confidence | (user req.) 12 | Done | Banner-derived observations are `suspected` only; tested |
| DA-09 | CVSS 4.0 + CWE mapping, deterministic | 12-13 | Done (M4) | Authoritative rule catalog `asvas/rules.py` (12 rules): CWE + name, OWASP Top 10 2021 category, CVSS 4.0 base vector (FIRST algorithm via `cvss`) or an explicit unscored reason; findings may only carry catalogued CWEs (enforced at write); cookie CWE follows the missing attribute (1004/614/1275); `/rules` endpoint. Tests `test_rules.py` (catalog ⇔ emitted rules, pinned scores, determinism). Base metrics only: environmental/threat metrics are not computed |
| DA-10 | Append-only, hash-chained audit ledger (WORM) | 6, 14, 42, 58, 63 | Partial (M3) | Hash-chained `audit_events`, UPDATE/DELETE blocked; `asvas audit-export` appends write-once (O_EXCL, 0444) JSONL segments with Ed25519-signed, hash-linked checkpoints (`audit_checkpoints`, append-only); `audit-verify-export` verifies offline with the public key only and `--db` cross-checks the live DB (detects owner/superuser deletion or edits). Tests `test_audit_export.py`. Open: a local directory is not WORM — deletion is detected, not prevented; S3 Object Lock (or equivalent) adapter not implemented; export is not scheduled automatically |
| DA-11 | Reports JSON/Markdown/PDF, via separate worker | 15-16 | Done (M2) | JSON/Markdown on demand; PDF rendered in memory by the separate `asvas report-worker`, SHA-256, audited; encryption of stored reports still open (CP-11) |
| DA-12 | Compliance mapping (NIST 800-53, ISO 27001, SOC2, OWASP) | 15, 59-61 | Planned (M4) | Not claimed |
| DA-13 | Redact secrets before external model; untrusted output treated as data | 22, 26, 55, 74, 78, 80 | Done | `redaction.py`; target text enters prompts only as escaped, truncated quoted data; tested |
| DA-14 | Retention 30 days for transient logs; partitioning | 77, 84-85 | Partial (M3) | `execution_log` range-partitioned by day (dispatch + per-request result lines; `/jobs/{id}/execution-log`); daily maintenance in the orchestrator (Redis-locked, once/day) creates partitions 7 days ahead, drops partitions older than retention+1 day via SECURITY DEFINER functions (DB refuses < 30 days), purges LangGraph checkpoints of assessments ended > 30 days, trims Redis Streams; purges audited per tenant. Evidence/findings/audit are not transient and are kept. Tests `test_retention.py`. Open: `audit_events`/`evidence` not partitioned; no long-term retention/deletion policy for evidence; var/logs file rotation not managed |
| DA-15 | Bloom-filter dedupe of discovery stream; streaming JSON parse | 30 | Done (M4, with substitution) | Per-assessment Redis-bitmap Bloom filter (2^20 bits, k=7, ~1 % FP at 110k items) in front of asset/relation upserts: definitely-new → write; maybe-seen → exact check, skip only identical records (false positives never drop data); stats in execution log. Streaming JSON: not applicable — executor results are protobuf (PO-06); instead results are size-capped (8 MiB base64) and rejected before decoding. Tests `test_dedupe.py` |

## 6. Dashboard / HITL UI

| ID | Requirement | Pages | Status | Notes |
|---|---|---|---|---|
| UI-01 | Responsive React dashboard with real-time execution graph, status, logs | 32, 43 | Done (M2) | Server-sent events of audit events (fetch-streamed, bearer header, Last-Event-ID resume) drive live refresh; polling fallback |
| UI-02 | HITL approval queue | 32 | Done | |
| UI-03 | Persona modes (junior vs advanced views) | 42-44 | Partial (M3) | Per-user Simplified/Advanced toggle. Simplified: Summary, prioritised "Fixes" (what we saw / what to do / confirmed-or-not / "Check if fixed" retest), Report. Advanced: plan graph, jobs with raw execution log, evidence, timeline, read-only Rego policy source. Display preference only (server permissions unchanged). Verified in Chromium via Playwright. Open: OPA policy customisation from the UI is not offered (policy changes stay code-reviewed); no intermediate persona |
| UI-04 | Read-only auditor dashboard | 60, 77-78 | Done (M3) | `auditor` role (read-only; every mutating endpoint refuses it) and `/compliance/controls`: live status of audit chain, signed export, approver signatures, dual control, encryption at rest, transport TLS, emergency stop, OPA policy digests, retention, isolation (Firecracker shown as missing). Tests `test_compliance.py`; UI checked in Chromium. Not a certification; framework mapping is DA-12 |

## 7. Operations / NFR (not claimed)

| ID | Requirement | Pages | Status |
|---|---|---|---|
| NF-01 | API p95 < 200 ms, 500 tenants, 1000 parallel microVMs, 99.9 % uptime, RTO 15 min, RPO 5 min | 50-51 | Aspirational — not measured |
| NF-02 | Precision ≥ 99 %, FP < 1 %, 80 % alert reduction, < 15 ms/endpoint | 39 | Aspirational — not measured, will not be displayed |
| NF-03 | EKS + bare-metal EC2, Terraform, Helm, Prometheus/Grafana, OpenTelemetry | 1, 32-33, 51, 83, 88-89 | Planned (M4); no paid infra will be provisioned automatically |
| NF-04 | Hash-pinned dependencies, image scanning in CI | 30, 79, 82 | Partial (M3) | Lockfiles (`uv.lock`, `go.sum`, `package-lock.json`); CI job `supply-chain` (`scripts/supply-chain.sh`) produces CycloneDX SBOMs for all three components and fails on known vulnerabilities (pip-audit, govulncheck call-graph reachable, npm audit). Local run 2026-11-07: 0 known vulnerabilities after upgrading golang.org/x/net to v0.62.0; one unreachable advisory remains (GO-2026-5932, x/crypto/openpgp, not imported; fix only in an unreleased pseudo-version). Open: container image scanning N/A (no images); Python export has no hashes in the SBOM input; SBOMs not signed |
| NF-05 | STRIDE threat model | 30 | Done | `docs/threat-model.md` |

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

---

## Verification map (milestone 1)

| Required verification | Automated test(s) |
|---|---|
| Scope rejection | `control-plane/tests/test_scope_and_tools.py` (CIDR breadth, out-of-scope IP/host/port/scheme, forbidden nets, loopback, protected ports, authorization window); `test_api_auth.py::test_scope_immutable_after_start_and_window_enforced`; `policies/asvas/decision_test.rego` |
| Redirect & destination validation | `test_integration.py::test_redirects_validated` (out-of-scope redirect blocked, never contacted; in-scope followed); `execution-plane/internal/netguard` tests; `worker_test.go::TestDNSRebindingDetected`, `TestCompromisedControlPlaneOutOfScopeDenied`, `TestProtectedPortDenied`, `TestKernelEgressBlocksNonAllowlisted` |
| Invalid tool parameters | `test_scope_and_tools.py::test_invalid_tool_params_rejected`; `worker_test.go::TestInvalidEnvelopesRejected` |
| Prompt injection in tool output | `test_planning.py::test_injected_proposals_rejected`; `test_lifecycle.py::test_hostile_planner_cannot_create_jobs`; `test_integration.py::test_complete_local_assessment_workflow` (injected banner/body stays evidence; no new targets) |
| Approval expiry & parameter mismatch | `test_lifecycle.py::test_approval_expiry_before_decision`, `test_approval_expiry_at_dispatch_requests_new_approval`, `test_parameter_change_after_approval_blocks_dispatch`, `test_approval_presented_hash_mismatch_invalidates`, `test_approval_flow_and_dual_control`; `worker_test.go::TestApprovalRequiredAndBoundToParams` |
| Duplicate job delivery | `test_lifecycle.py::test_duplicate_stale_and_forged_results_ignored`, `test_orchestrator_loop_processes_streams`; `test_integration.py::test_duplicate_job_delivery_executes_once`; `worker_test.go::TestHaltedAndDuplicate` |
| Worker timeout & cancellation | `test_integration.py::test_worker_timeout_is_bounded`, `test_cancellation_kills_running_worker`, `test_emergency_stop_kills_running_worker`; `test_lifecycle.py::test_reaper_times_out_lost_jobs`, `test_failure_retry_is_bounded`; `worker_test.go::TestTimeoutKillsSandbox`, `TestCancellationKillsRunningJob` |
| AuthN/AuthZ boundaries | `test_api_auth.py` (401s, forged token, role-claim escalation, role matrix, cross-tenant API + RLS, cross-tenant insert, rate limit) |
| Evidence-to-finding linkage | `test_lifecycle.py::test_full_simulated_run_and_evidence_linkage`; `test_integration.py::test_complete_local_assessment_workflow`, `test_retest_marks_resolved` |
| Complete local workflow | `test_integration.py::test_complete_local_assessment_workflow`; `scripts/demo.py`; Playwright UI run (manual, see progress.md) |
| Honest model failure | `test_planning.py::test_anthropic_provider_invalid_output_is_honest_error`, `test_anthropic_provider_timeout`; `test_lifecycle.py::test_provider_failure_is_reported_honestly`, `test_opa_unavailable_fails_closed` |
| Durability / recovery | `test_lifecycle.py::test_planning_checkpoints_are_durable`, `test_lost_planning_request_is_recovered`, `test_concurrent_planning_is_locked` |
| M2 additions | `test_graphstore.py` (projection, tenant isolation, failure tolerance), `test_integration.py::test_tls_configuration_check`, `checks/tls_test.go`, `test_reports.py`, `test_events.py`, `test_lifecycle.py::test_execution_plane_scope_denial_locks_assessment`, `worker_test.go::TestKernelEgressRequirementEnforced`, `test_planning.py::test_circuit_breaker_opens_and_recovers`, `test_fallback_is_labelled_not_ai` |
| M3 additions | `tests/test_wire.py` (round trip, tamper, unknown fields, typed params), `worker_test.go::TestInvalidEnvelopesRejected` (signed unknown field, params/tool mismatch), `grpcserver/server_test.go` (no cert, foreign CA, wrong identity, TLS 1.2, unsigned control), `test_integration.py::test_executor_grpc_status_over_mtls`, `test_cancellation_delivered_over_grpc_only` |
