# ASVAS security review — 2026-11-08

**Scope:** control plane (Python), execution plane (Go), dashboard (React), local service configuration.
**Reviewer:** the development assistant that wrote the code. This is a *self-review*: it is useful but does not
replace an independent review or penetration test, which is still outstanding.

## Method

| Step | Tool / approach | Result |
|---|---|---|
| Static analysis, Python | bandit 1.8.6 (`bandit -r control-plane/asvas`) | 10 issues, all triaged below |
| Static analysis, Go | gosec v2.22.8 (`gosec -exclude-dir=gen ./...`) | 36 issues, all triaged below |
| Dependencies | `scripts/supply-chain.sh` (pip-audit, govulncheck, npm audit) | 0 known vulnerabilities |
| Manual review | authentication, authorization, tenant isolation, browser hardening, secrets handling | 5 findings fixed (SR-1..SR-5) |
| Regression tests | `control-plane/tests/test_security_review.py` + browser check of the production build | pass |

## Fixed findings

| ID | Severity | Finding | Fix | Verified by |
|---|---|---|---|---|
| SR-1 | Medium | API responses carried no hardening headers (nosniff, framing, caching of sensitive JSON, CSP, HSTS). | Middleware adds `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `CORP`, `CSP: default-src 'none'` and HSTS when TLS is on. | `test_sr1_*` |
| SR-2 | Medium | CORS origins were hard-coded to localhost in every environment. | `ASVAS_CORS_ORIGINS` setting; production refuses to start with localhost origins. | `test_sr2_*` |
| SR-3 | Medium | OIDC tokens without an `azp` claim were accepted, so a token issued to another client of the same realm with audience `asvas-api` would work. | `azp` must equal the dashboard client id. | `test_sr3_*`, live SSO e2e |
| SR-4 | Low | OpenAPI schema and Swagger UI were served in every environment (API surface disclosure). | Only in development. | `test_sr4_*` |
| SR-5 | Medium | The dashboard had no Content-Security-Policy; the bearer token lives in sessionStorage, so any XSS could read it. | Production build injects a strict CSP (`script-src 'self'`, `connect-src`/`form-action` limited to self + the OIDC issuer, `object-src 'none'`, `base-uri 'none'`). | Built dashboard driven in Chromium: dev login, assessment views and full SSO + TOTP flow with zero CSP/console errors |
| SR-6 | Low | `assert` used for control flow in the planning graph (removed under `python -O`). | Explicit `LookupError`. | Python suite |

## Triaged static-analysis results (accepted, with reason)

| Tool / rule | Where | Decision |
|---|---|---|
| bandit B608 (SQL built from strings) ×6 | `api/app.py`, `keymgmt.py`, `retention.py`, `statemachine.py` | False positive: only column/table names from fixed literals in the code are interpolated; all values are bound parameters. |
| bandit B406 (`xml.sax.saxutils.escape`) | `report_worker.py` | False positive: used to *escape output* for the PDF renderer, not to parse XML. |
| gosec G402 (InsecureSkipVerify) | `checks/tls.go` | Intended: the TLS check must complete handshakes with untrusted certificates to record them; the chain is verified explicitly afterwards and the result reported. |
| gosec G115 (int→int32/uint32) ×15 | protobuf conversion, framing, UID | Values are bounded before conversion (ports ≤ 65535, body excerpt ≤ 64 KiB, request counts ≤ policy caps, frame size ≤ 4 MiB checked first, UIDs from config). |
| gosec G204 / G304 (exec / file path from variable) ×8 | sandbox re-exec, jailer, policy, certs | Paths come from executor configuration, never from job input. |
| gosec G301 / G302 (permissions) ×5 | Firecracker jail staging, cgroup dir | Jail files are 0444 and must be readable by the jailed uid; cgroup directories must be traversable. |
| gosec G104 (unchecked errors) ×7 | cleanup paths (close/kill/remove) | Best-effort cleanup; failures do not affect security decisions. |

## Areas reviewed with no new finding

* **Authorization:** role checks on every mutating endpoint (`test_api_auth.py`, auditor read-only tests); dual control and
  signed approvals (PO-04).
* **Tenant isolation:** PostgreSQL RLS with FORCE on all tenant tables incl. new ones (approver_keys, audit_checkpoints,
  execution_log, blocked_paths); app role cannot read partitions directly; Qdrant tenant filter re-checked; MCP tenant-scoped.
* **Secrets:** key ring, ledger key, Keycloak/Qdrant secrets created 0600 under `var/` (git-ignored); repository grep for
  private keys/tokens clean; redaction before any model call.
* **Execution plane:** signed envelopes, re-validation, DNS pinning, nftables egress, per-run credentials, eBPF syscall monitor.

## Still open (not fixed by this review)

1. Independent review / penetration test by someone other than the author.
2. Access token in sessionStorage (mitigated by CSP); a backend-for-frontend with httpOnly cookies would remove it.
3. No refresh tokens: users re-authenticate after the 10-minute access-token lifetime.
4. Firecracker backend not exercised on KVM (PO-10).
