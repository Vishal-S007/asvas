# Local demo walkthrough

Everything targets the bundled local test target (`test-target/target.py`, 127.0.0.1 only). Expected
outcomes are in [test-target/EXPECTED.md](../test-target/EXPECTED.md). Do not point ASVAS at systems you are
not authorized to test.

1. Start the stack (`sudo ./scripts/dev-up.sh`) and the dashboard (`cd dashboard && npm run dev`).
2. Open http://127.0.0.1:5173 → **Development sign-in** → *Olu Operator*.
3. **Workers & policy**: confirm one executor is *alive*, backend `devprocess`, egress
   `nftables-per-uid+app-pinned`, OPA *reachable / policy loaded*, and the list of unavailable features.
4. **Assessments → New assessment**. Defaults target `127.0.0.1` ports 18080 (weak) and 18081 (hardened),
   allowed CIDR `127.0.0.1/32`. Fill the authorization statement, reference and authorizer. Keep
   "Require human approval for medium-risk actions" checked. **Create draft**, then **Start assessment**.
5. The deterministic planner runs round 0 (`http.security_headers`, low risk → runs automatically) and
   round 1 (`http.allowed_methods`, medium → paused). Status becomes **awaiting approval**.
6. Try approving as the operator (API returns 403: requester cannot approve). Sign out, sign in as
   *Arun Approver* → **Approval queue** → inspect target, parameters and the binding hash → **Approve** both.
7. The assessment completes. Tabs:
   - **Plan graph** — objective → planning rounds → steps coloured by job status.
   - **Jobs** — policy decision, attempts, executor backend/egress mode per job.
   - **Findings** — 6 findings on :18080 only; banner and advertised methods are *suspected*; open evidence
     to see the raw exchange, its SHA-256 and integrity status (the injected "ignore previous instructions"
     banner is visible only as untrusted evidence).
   - **Timeline** — every transition, policy decision (control and execution plane), dispatch and result.
   - **Report** — JSON/Markdown with evidence hashes, retest history, audit-chain check and limitations.
8. **Retest**: create the flag file the target watches (`TARGET_FIXED=1` restart, or see
   `tests/test_integration.py::test_retest_marks_resolved`) and press **Request retest** → finding becomes *resolved*.
9. **Cancellation / emergency stop**: as admin (*Ada Admin*) use **Emergency stop** in the top bar; active
   assessments move to *cancelling → cancelled* and running sandbox processes are killed. **Reset** re-enables work.
10. **Audit history → Verify hash chain**.

Scripted equivalent of steps 4–7: `python3 scripts/demo.py`.
