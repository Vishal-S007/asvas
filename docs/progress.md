# Progress Log

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
