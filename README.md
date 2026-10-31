# ASVAS — Autonomous Security Validation Agent System (Milestones 1–2)

A security validation platform for **explicitly authorized** environments: it accepts an assessment scope and
testing policy, creates a bounded plan, runs permitted non-destructive checks through controlled tool adapters,
stores real evidence, derives evidence-backed findings, pauses for human approvals, supports retesting, and keeps
a hash-chained audit trail.

> **Status: development milestones 1–2. Not production-ready and not enterprise-ready.** See
> [docs/requirements.md](docs/requirements.md) for what is implemented, partial, substituted, or planned, and
> [Limitations](#limitations) below.

## Architecture (short)

| Plane | Where | Tech |
|---|---|---|
| Management | `dashboard/` | React 19 + Vite + TypeScript |
| Control (modular monolith) | `control-plane/asvas/` | Python ≥3.11, FastAPI, SQLAlchemy/Alembic, LangGraph (Postgres checkpoints) |
| Policy | `policies/` | OPA/Rego v1 — evaluated by an OPA server *and* independently inside the executor |
| Execution | `execution-plane/` | Go 1.26 executor, embedded OPA, pinned-IP HTTP checks, dev process sandbox + nftables |
| State / events | — | PostgreSQL 16 (RLS, source of truth), Redis Streams, Neo4j 5.26 (graph projection) |
| Reports | `asvas report-worker` | JSON / Markdown / PDF (separate rendering worker) |

Details: [docs/architecture.md](docs/architecture.md) · threat model: [docs/threat-model.md](docs/threat-model.md) ·
plan: [docs/implementation-plan.md](docs/implementation-plan.md) · progress log: [docs/progress.md](docs/progress.md).

## Local setup

Prerequisites: PostgreSQL 16, Redis ≥7, Neo4j 5.26 (optional; or `docker compose up` for all dependencies — compose file untested), [uv](https://docs.astral.sh/uv/), Go ≥1.26, Node 22, OPA 1.21.x, `nft`
(optional; executor must run as root to use per-UID sandbox + nftables egress — otherwise it runs *degraded* and says so).

```bash
# 1. database roles + databases (development credentials only)
sudo -u postgres psql -f scripts/db-bootstrap.sql
# 2. OPA binary (or install from openpolicyagent.org) into .tools/
GOBIN=$PWD/.tools go install github.com/open-policy-agent/opa@v1.21.4
# 3. config
cp .env.example .env            # dev placeholders; never commit .env
# 4. control plane deps
(cd control-plane && uv sync --frozen)
# 5. start OPA, API, orchestrator, executor and the local test target (logs in var/logs/)
sudo ./scripts/dev-up.sh        # root only needed for sandbox UID drop + nftables
# 6. dashboard
(cd dashboard && npm ci && npm run dev)   # http://127.0.0.1:5173
./scripts/dev-down.sh           # stop everything
```

Walkthrough: [docs/demo.md](docs/demo.md). Scripted version: `python3 scripts/demo.py`.

## Tests

```bash
(cd policies && ../.tools/opa test -v .)                  # 21 Rego policy tests
(cd execution-plane && sudo go test ./...)                # 19 executor tests: isolation, approvals, rebinding, TLS, cancel
(cd control-plane && uv run pytest)                       # 93: unit, API, lifecycle, Neo4j, SSE, PDF, E2E with real executor
(cd dashboard && npm run typecheck && npm run build)
```

CI: `.github/workflows/ci.yml` (not yet run — no remote repository configured).

## Safety model in one paragraph

Model output is only a *proposal* (tool id + typed params). It becomes a job only after deterministic
validation (scope, schema, dedupe, Tarjan cycle check, depth/budget caps) and an OPA decision; before execution
the Go executor verifies the HMAC-signed envelope, re-validates parameters, resolves DNS once, checks every
address, re-evaluates the same Rego policy, verifies any approval token is bound to the exact parameters, and runs
the check in a sandbox child whose egress is limited by nftables to pre-validated `ip:port` pairs. Target content
is stored as evidence and never changes scope, policy or tools. There is no shell tool.

## Limitations

- **Isolation:** the execution backend is an approved *development substitute* (separate UID, no capabilities,
  `no_new_privs`, rlimits, process-group kill, nftables per-UID egress). It shares the host kernel and is **not
  equivalent to Firecracker microVMs**; Firecracker and the eBPF monitor are open requirements (need a KVM host).
- Three checks exist (`http.security_headers`, `http.allowed_methods`, `tls.configuration`). Absence of findings ≠ security.
- Planner: the default `deterministic-test` provider is **not AI** and is labelled as such everywhere. The
  Anthropic provider is implemented and unit-tested with mocked HTTP only; it has not been run against a live API.
- Not yet implemented: Qdrant, OIDC/MFA, mTLS, encryption at rest/KMS, gRPC contract, CVSS environmental/threat
  metrics, compliance mapping, WORM export, multi-stage path analysis, Kubernetes/Terraform. No performance/accuracy figures from
  the specification have been measured or are claimed.
- Dev login exists only with `ASVAS_ENV=development`.
