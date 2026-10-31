"""Schema-first reports (spec pp. 14-16): JSON built only from stored state, Markdown rendered from the JSON."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import Connection

from asvas.audit import verify_chain
from asvas.db import row, rows

LIMITATIONS = [
    "Execution backend is the development process sandbox (non-root UID, no_new_privs, rlimits, nftables egress); "
    "it is NOT equivalent to the Firecracker microVM + eBPF isolation in the specification.",
    "Only HTTP configuration checks are implemented; absence of a finding is not evidence of security.",
    "Banner- and advertisement-based observations are 'suspected' and were not verified.",
    "Severity is a fixed rule table; CVSS 4.0 scores are base-only (CVSS-B) vectors assigned per rule, computed with "
    "the FIRST algorithm, without threat/environmental metrics and without exploitation.",
    "Evidence is stored unencrypted in PostgreSQL in this milestone.",
]


def build_report(conn: Connection, tenant_id, assessment_id) -> dict[str, Any] | None:
    a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=str(assessment_id))
    if a is None:
        return None
    findings = rows(conn, "SELECT f.*, s.identifier AS asset FROM findings f JOIN assets s ON s.id = f.asset_id "
                          "WHERE f.assessment_id = :a ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                          "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at", a=str(assessment_id))
    out_f = []
    for f in findings:
        ev = rows(conn, "SELECT id, sha256, job_id, attempt, seq, created_at FROM evidence WHERE id = ANY(:ids)",
                  ids=list(f["evidence_ids"]))
        rt = rows(conn, "SELECT outcome, job_id, created_at, completed_at, evidence_ids FROM finding_retests "
                        "WHERE finding_id = :f ORDER BY created_at", f=str(f["id"]))
        out_f.append({
            "id": str(f["id"]), "title": f["title"], "asset": f["asset"], "check_id": f["check_id"],
            "rule_id": f["rule_id"], "assessment_id": str(assessment_id), "observed_at": f["created_at"].isoformat(),
            "observed_behavior": f["observed_behavior"], "severity": f["severity"],
            "severity_rationale": f["severity_rationale"], "confidence": f["confidence"],
            "verification_status": f["verification_status"], "state": f["state"], "cwe": f["cwe"],
            "remediation": f["remediation"],
            "cvss": {"vector": f["cvss_vector"], "base_score": float(f["cvss_score"]) if f["cvss_score"] is not None else None,
                     "severity": f["cvss_severity"], "type": "CVSS-B (base only; rule-assigned)"} if f["cvss_vector"] else None,
            "evidence": [{"id": str(e["id"]), "sha256": e["sha256"], "job_id": str(e["job_id"]), "attempt": e["attempt"],
                          "seq": e["seq"]} for e in ev],
            "retest_history": [{"outcome": r["outcome"], "job_id": str(r["job_id"]),
                                "requested_at": r["created_at"].isoformat(),
                                "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
                                "evidence_ids": [str(x) for x in r["evidence_ids"]]} for r in rt],
        })
    jobs = rows(conn, "SELECT status, count(*) n FROM jobs WHERE assessment_id = :a GROUP BY status", a=str(assessment_id))
    return {
        "report_version": 1,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "assessment": {"id": str(a["id"]), "name": a["name"], "status": a["status"],
                       "started_at": a["started_at"].isoformat() if a["started_at"] else None,
                       "finished_at": a["finished_at"].isoformat() if a["finished_at"] else None,
                       "authorization": a["scope"]["authorization"], "targets": a["scope"]["targets"],
                       "planner": {"provider": a["provider_name"], "is_live_ai": a["provider_is_live_ai"],
                                   "note": None if a["provider_is_live_ai"] else
                                   "Planned by the deterministic test provider — this is NOT an AI assessment."},
                       "requests_used": a["requests_used"], "tokens_used": a["tokens_used"],
                       "failure_reason": a["failure_reason"]},
        "jobs": {r["status"]: r["n"] for r in jobs},
        "findings": out_f,
        "audit_chain": verify_chain(conn, tenant_id),
        "limitations": LIMITATIONS,
    }


def render_markdown(rep: dict[str, Any]) -> str:
    a = rep["assessment"]
    lines = [f"# Assessment report: {a['name']}", "",
             f"- Assessment ID: `{a['id']}`  ", f"- Status: **{a['status']}**  ",
             f"- Window: {a['started_at']} → {a['finished_at']}  ",
             f"- Authorization: {a['authorization']['reference']} by {a['authorization']['authorized_by']}  ",
             f"- Planner: {a['planner']['provider']} (live AI: {a['planner']['is_live_ai']})  "]
    if a["planner"]["note"]:
        lines.append(f"- **Note:** {a['planner']['note']}  ")
    if a["failure_reason"]:
        lines.append(f"- Failure reason: {a['failure_reason']}  ")
    lines += [f"- Audit chain intact: {rep['audit_chain']['ok']} ({rep['audit_chain']['events']} events)", "",
              "## Findings", ""]
    if not rep["findings"]:
        lines.append("No findings were recorded by the implemented checks.")
    for f in rep["findings"]:
        lines += [f"### [{f['severity'].upper()}] {f['title']}", "",
                  f"- Asset: `{f['asset']}` · Check: `{f['check_id']}` / `{f['rule_id']}` · {f['cwe'] or ''}",
                  f"- Verification: **{f['verification_status']}** · Confidence: {f['confidence']} · State: {f['state']}",
                  f"- Observed: {f['observed_behavior']}", f"- Severity rationale: {f['severity_rationale']}",
                  f"- CVSS 4.0: {f['cvss']['base_score']} ({f['cvss']['severity']}) `{f['cvss']['vector']}` — base metrics only"
                  if f["cvss"] else "- CVSS 4.0: not scored for this rule",
                  f"- Remediation: {f['remediation']}",
                  "- Evidence: " + ", ".join(f"`{e['id']}` (sha256 `{e['sha256'][:16]}…`)" for e in f["evidence"])]
        for r in f["retest_history"]:
            lines.append(f"- Retest {r['requested_at']}: {r['outcome']}")
        lines.append("")
    lines += ["## Limitations", ""] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(lines) + "\n"
