# Progress Log

## 2026-11-07 — Milestone 3 (hardening without new infrastructure) — in progress

### Completed
- Protobuf contract `asvas.execution.v1` (PO-06): typed JobEnvelope with a params oneof per tool, JobResult,
  ControlMessage; HMAC over serialized bytes; unknown fields rejected on both planes; generated code committed and
  reproducible (`scripts/gen-proto.sh`, CI drift check). The JSON envelope path was removed (single format).
- `ExecutorService` gRPC (GetStatus, Control) on every executor, mutual TLS 1.3 with SPIFFE-URI authorization
  (CP-10 partial); dev PKI script; control plane probes executors over mTLS for `/system/status` and delivers
  cancel/emergency-stop both on the signed stream and directly over gRPC; dashboard shows the channel state.

### Verification (2026-11-07, this sandbox, root)
- OPA 21/21; Go 21 tests pass (adds mTLS server tests); Python 99 pass (adds wire contract and gRPC E2E tests:
  status over mTLS, cancellation delivered over gRPC only, forged control refused); dashboard tsc + build OK;
  `scripts/demo.py` on the live stack (protobuf wire + mTLS) gives the 6 expected findings, audit chain intact.

### Next
OIDC sign-in (CP-07) needs a decision: which identity provider (e.g. Keycloak locally, Google, Microsoft Entra).

## 2026-10-31 — Milestone 2 (correlation & depth) — in progress

### Completed in M2 (each committed after its checks passed)
- `a352e2f` Neo4j 5.26.12 graph projection (DA-03): idempotent, tenant-scoped, failure-tolerant (audited), resync CLI,
  topology view in dashboard. PostgreSQL remains source of truth.
- `1f5bf94` `tls.configuration` check (PO-17): Go handshake probes (default + TLS 1.0/1.1-only), deterministic TLS rules,
  https-only in Rego; local target gained a weak TLS port (self-signed, `localhost`-only SAN, 10-day cert, TLS 1.0+).
- `6ff05c9` Scope-violation lockdown (SC-06), `require_kernel_egress` per-run isolation requirement (SC-08),
  Redis token-bucket rate limiter (CP-06), provider circuit breaker + explicit, labelled deterministic fallback (PL-07).
- `d7d0fd8` CVSS 4.0 base scores per rule via FIRST algorithm (`cvss` library, LGPLv3+); suspected findings unscored (DA-09 partial).
- `85f22f3` PDF reports rendered in memory by a separate `asvas report-worker` (DA-11).
- `2192d12` Live server-sent event stream + streaming dashboard client (UI-01); fixed scope check for one host listed
  in several target entries.

### Verification (2026-10-31, this sandbox, root)
- OPA: `opa check --strict` OK, `opa test` **21/21**.
- Go: gofmt/vet clean, **19 tests pass** (adds TLS probe + kernel-egress requirement tests).
- Python: ruff clean, **93 pytest pass** (adds Neo4j, TLS E2E with real executor, CVSS, PDF worker, SSE, lockdown,
  circuit breaker tests). Neo4j tests ran against a real local Neo4j 5.26.12.
- Dashboard: `tsc` clean, `vite build` OK; Playwright run of HTTP+TLS assessment → live stream → findings →
  Neo4j topology → PDF render/download: no console errors (one duplicate-key warning found and fixed).

### Not verified
- `docker-compose.yml` (no Docker daemon here); GitHub Actions (no remote); Anthropic provider live.

### Exact next task
M3 preparation that needs no new infrastructure: gRPC/protobuf execution contract (PO-06) replacing the JSON
envelope schema, with the HMAC signature kept over the serialized bytes.

## 2026-10-31 — Milestone 1 (first runnable vertical slice) — complete

Branch `feature/m1-vertical-slice` (local only; no remote configured — see "Unresolved decisions").

### What works
- Assessment + scope + testing-policy persistence (PostgreSQL 16, Alembic, RLS with `FORCE`, non-owner app role).
- Signed, immutable scope at start; authorization window enforced.
- LangGraph planning (deterministic test provider, labelled not-AI; Anthropic provider implemented, mock-tested only),
  deterministic proposal validation (scope, schema, dedupe, Tarjan, depth/budgets), Postgres checkpoints.
- OPA policy evaluated twice: OPA server (control plane) and embedded OPA in the Go executor.
- Redis Streams job lifecycle with HMAC-signed envelopes/results/control messages, claim keys, bounded retries,
  reaper, planning recovery, cancellation, tenant emergency stop that kills running sandboxes.
- Approvals bound to (assessment, job, tool, target, params) + expiry, single-use, dual control, verified again by executor.
- Go executor: strict decode, DNS resolve-once + pinning + rebinding check, redirect validation, dev process sandbox
  (approved Firecracker substitute), nftables per-UID egress with startup self-test.
- Evidence (append-only, SHA-256), asset correlation, deterministic finding rules (confirmed vs suspected), retests.
- JSON/Markdown reports; hash-chained audit ledger with verification.
- React dashboard: login (dev), assessments, creation form, status/timeline, plan graph, jobs, approval queue,
  findings + evidence drawer, retest, assets, reports, workers & policy, audit, cancel, emergency stop;
  loading/empty/error/permission-denied states; unavailable features labelled.

### Verification (exact outcomes, 2026-10-31, this sandbox, running as root)
- `opa check --strict` OK; `opa test`: **19/19 pass**.
- Go: `gofmt` clean, `go vet` clean, `go test ./...`: **16 tests pass** (canonical, netguard, policy, worker incl. kernel egress).
- Python: `ruff` clean; `pytest`: **76 pass** (incl. 7 integration tests with the real Go executor, OPA, Redis, Postgres, test target).
- Dashboard: `tsc --noEmit` clean; `vite build` OK.
- Manual: Playwright drive of the full UI flow (operator → approver → findings/evidence/report/audit, viewer
  permission-denied, mobile width) — no console errors.
- `scripts/demo.py` against the live stack: 4 jobs, 6 findings as in `test-target/EXPECTED.md`, audit chain OK.

### Not verified
- GitHub Actions workflow has never run (no remote). Non-root execution of the Go tests/integration suite
  (degraded sandbox path) was not run here; CI runs Go tests with sudo and pytest non-root.
- Anthropic provider against the live API (no key configured; deliberately not used).

### Unresolved decisions
- Repository URL + GitHub auth (session token invalid). Push pending.
- KVM-capable host for Firecracker backend (PO-10) and eBPF monitor (PO-12).

### Exact next task
M2 step 1: implement the Neo4j `GraphStore` adapter behind the existing asset-correlation calls
(`asvas/evidence.py::correlate_assets`), with a docker-compose service definition and tests, keeping Postgres
as the source of truth.

### M3 — CP-10 local service TLS (2026-11-07)
- Done: dev CA now carries critical CA/keyUsage extensions (Python 3.13 strict X.509 rejected the old one).
- PostgreSQL TLS 1.3 required; Redis TLS-only :6380; OPA HTTPS (TLS 1.3 min); API HTTPS. `.env.example` defaults to TLS.
- Tested: `tests/test_service_tls.py` 6 passed (pg_stat_ssl TLSv1.3, plaintext rejected, Redis TLSv1.3, wrong CA rejected,
  production refuses `redis://`, API TLS handshake). Full suites under TLS: Python 110 passed, Go all packages ok, OPA 21/21.
  Demo over HTTPS: 6 findings, audit chain ok.
- Incomplete: Neo4j bolt TLS; API not pinned to TLS 1.3; no Vault-managed CA or rotation.

### M3 — PO-04 per-approver signatures (2026-11-07)
- Done: migration 0005 (`approver_keys`, signature columns on `approvals`); `asvas/signatures.py`; `/approver-keys` register/list/revoke;
  decisions refused (403, audited, approval stays PENDING) without a valid signature from the deciding user's active key.
- Dashboard signs with a non-extractable WebCrypto Ed25519 key stored in IndexedDB. Interop checked: Chromium 153 signature verified by
  the server code; tampered message rejected.
- Tested: `test_approver_signatures.py` 7 passed (recording, unsigned refused, cross-decision/binding/expiry replay refused, other user's
  key refused, revoked key refused, signed rejection, key validation). Demo: unsigned approval -> 403, signed -> APPROVED, 6 findings.
- Incomplete: WebAuthn (hardware-backed keys, attestation); executor-side signature verification.

### M3 — DA-10 signed audit export (2026-11-07)
- Done: migration 0006 (`audit_checkpoints`, append-only); `asvas/audit_export.py`; CLI `audit-export`, `audit-public-key`,
  `audit-verify-export [--db]`. Ledger key `var/keys/audit-signing.pem` (0600, created in dev, required in production).
- Tested: `test_audit_export.py` 9 passed (incremental chain, write-once, tampered segment, forged checkpoint, deleted checkpoint,
  wrong key, DB owner deletes an event with the trigger disabled -> cross-check reports it, checkpoint rows append-only, key mode).
  Dev stack: 460 events exported and cross-checked OK.
- Incomplete: immutable storage backend (Object Lock); scheduled export.

### M3 — DA-14 retention and partitioning (2026-11-07)
- Done: migration 0007 (`execution_log` partitioned by day, RLS; partition functions with a 30-day floor); `asvas/retention.py`;
  orchestrator runs it daily; CLI `asvas retention`; API `/jobs/{id}/execution-log`.
- Tested: `test_retention.py` 6 passed (dispatch log line, only partitions > 31 days dropped + audited, floor enforced in DB and config,
  app role cannot read partitions directly, old checkpoints purged, stream trim + once-per-day lock). Full Python suite 132 passed.
- Incomplete: partitioning of `audit_events`/`evidence`; evidence retention policy; log-file rotation.

### M3 — DA-05 / PL-05 / PL-09 (2026-11-07)
- Done: `orchestration/memory.py` (short-term Redis memory with TTL, erased at end); path blocking after 3 consecutive failures;
  per-step cost ceiling and per-assessment cost budget (migration 0008); live provider refuses without configured prices.
- Tested: `test_planning_controls.py` 11 passed. Full Python suite 142 passed.
- Not claimed: no real model was called; cost logic is tested with mocked responses only.

### M3 — PL-10 specialised agents (2026-11-07)
- Done: `planning/agents.py`; graph nodes per agent; sub-schema enforcement in `validate_proposal`; agent-namespaced step ids.
- Tested: `test_agents.py` 3 passed (agents see only their tools, cross-role proposals rejected with PL-10 reason, agents with no
  permitted tools are not called). Full Python suite 145 passed.

### M3 — UI-03 / UI-04 (2026-11-07)
- Done: migration 0009 (`auditor` role) + seeded `auditor@acme.test`; `asvas/compliance.py`; `/compliance/controls`, `/system/policy`;
  dashboard persona toggle, Summary/Fixes views, job execution log, policy viewer, Controls page.
- Tested: `test_compliance.py` 4 passed; Playwright run against the TLS dev stack: auditor sees 10 controls and no emergency-stop button;
  operator Simplified shows Summary/Fixes/Report with 6 prioritised fixes; Advanced shows all tabs, job log lines and policy file.
  No browser console errors. Full Python suite 149 passed.
- Observed on the long-lived dev DB: controls flag pre-M3 data honestly (8 of 12 decisions unsigned, 28 of 40 evidence records
  stored before encryption existed).

### M3 — NF-04 SBOM and dependency scanning (2026-11-07)
- Done: `scripts/supply-chain.sh`, CI job `supply-chain` (uploads SBOMs + scan results as an artifact).
- Tested locally: SBOMs control-plane (72 components, CycloneDX 1.6), execution-plane (34, 1.6), dashboard (6, 1.5);
  pip-audit 69 packages / 0 vulns; npm audit 0; govulncheck 0 reachable (after x/net 0.60 -> 0.62; Go tests re-run, pass).
  Confirmed pip-audit exits 1 on a deliberately vulnerable requirement. The CI job itself has not run yet (no push from here).

## M4 batch (started 2026-11-08 03:30 IST)

### CP-07 OIDC SSO + MFA with Keycloak
- Done: `scripts/keycloak-dev.sh` (start/setup/stop; realm `asvas`, PKCE client, audience + AMR mappers, TOTP required, roles,
  dev users with random passwords in var/keycloak/, 0600); `asvas/auth.py` OIDC validation; `/auth/config`; dashboard PKCE flow.
- Tested: `test_oidc.py` 17 passed (valid token; wrong issuer/audience/client/expiry/unverified e-mail/no otp/unknown user/role
  mismatch/wrong key/alg none; dev tokens refused in production; production config checks).
  Live e2e (Chromium -> Keycloak -> API): returning user with password + TOTP -> amr ["pwd","otp"], /me OK (operator, auditor);
  first-time user enrols TOTP -> enrolment-only token refused (no otp) -> forced re-login with code -> OK (approver, globex operator).
- Full Python suite 166 passed.
