"""Explicit, validated state transitions for assessments and jobs (spec pp. 2, 64-65, 72)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Connection, text

from asvas import audit

ASSESSMENT_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT": {"PLANNING", "CANCELLED"},
    "PLANNING": {"RUNNING", "AWAITING_APPROVAL", "REPORTING", "FAILED", "CANCELLING"},
    "RUNNING": {"AWAITING_APPROVAL", "PLANNING", "REPORTING", "FAILED", "CANCELLING"},
    "AWAITING_APPROVAL": {"RUNNING", "PLANNING", "REPORTING", "FAILED", "CANCELLING"},
    "REPORTING": {"COMPLETED", "FAILED"},
    "COMPLETED": {"RUNNING"},          # retest re-opens execution on a completed assessment
    "CANCELLING": {"CANCELLED"},
    "FAILED": set(),
    "CANCELLED": set(),
}
ASSESSMENT_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
ASSESSMENT_ACTIVE = {"PLANNING", "RUNNING", "AWAITING_APPROVAL", "REPORTING", "CANCELLING"}

JOB_TRANSITIONS: dict[str, set[str]] = {
    "PROPOSED": {"DENIED", "AWAITING_APPROVAL", "QUEUED", "CANCELLED"},
    "AWAITING_APPROVAL": {"QUEUED", "DENIED", "CANCELLED"},
    "QUEUED": {"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "DENIED", "AWAITING_APPROVAL"},
    "RUNNING": {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "DENIED"},
    "FAILED": {"QUEUED"},              # bounded re-dispatch (attempt < max_attempts)
    "TIMED_OUT": {"QUEUED"},
    "SUCCEEDED": set(),
    "DENIED": set(),
    "CANCELLED": set(),
}
JOB_TERMINAL = {"SUCCEEDED", "DENIED", "CANCELLED"}
JOB_OPEN = {"PROPOSED", "AWAITING_APPROVAL", "QUEUED", "RUNNING"}


class IllegalTransition(Exception):
    pass


def transition_assessment(conn: Connection, tenant_id, assessment_id, to: str, actor: str,
                          reason: str | None = None, extra: dict[str, Any] | None = None,
                          expected_from: set[str] | None = None) -> str:
    cur = conn.execute(text("SELECT status FROM assessments WHERE id = :id FOR UPDATE"),
                       {"id": str(assessment_id)}).scalar()
    if cur is None:
        raise IllegalTransition("assessment not found")
    if (expected_from and cur not in expected_from) or to not in ASSESSMENT_TRANSITIONS[cur]:
        audit.record(conn, tenant_id, actor, "assessment.transition_rejected",
                     {"from": cur, "to": to, "reason": reason}, assessment_id)
        raise IllegalTransition(f"assessment {cur} -> {to} not allowed")
    sets = ["status = :to", "updated_at = now()", "version = version + 1"]
    if to in ASSESSMENT_TERMINAL:
        sets.append("finished_at = now()")
    if to == "FAILED" and reason:
        sets.append("failure_reason = :reason")
    conn.execute(text(f"UPDATE assessments SET {', '.join(sets)} WHERE id = :id"),
                 {"to": to, "id": str(assessment_id), "reason": reason})
    audit.record(conn, tenant_id, actor, "assessment.transition",
                 {"from": cur, "to": to, "reason": reason, **(extra or {})}, assessment_id)
    return cur


def transition_job(conn: Connection, tenant_id, job_id: uuid.UUID | str, to: str, actor: str,
                   reason: str | None = None, extra: dict[str, Any] | None = None) -> str:
    r = conn.execute(text("SELECT status, assessment_id, attempt FROM jobs WHERE id = :id FOR UPDATE"),
                     {"id": str(job_id)}).first()
    if r is None:
        raise IllegalTransition("job not found")
    cur, assessment_id, attempt = r
    if to not in JOB_TRANSITIONS[cur]:
        audit.record(conn, tenant_id, actor, "job.transition_rejected",
                     {"job_id": str(job_id), "from": cur, "to": to, "reason": reason}, assessment_id)
        raise IllegalTransition(f"job {cur} -> {to} not allowed")
    sets = ["status = :to"]
    if to in ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "DENIED"):
        sets.append("finished_at = now()")
    if to == "RUNNING":
        sets.append("started_at = COALESCE(started_at, now())")
    if reason and to in ("FAILED", "TIMED_OUT", "DENIED", "CANCELLED"):
        sets.append("error = :reason")
    conn.execute(text(f"UPDATE jobs SET {', '.join(sets)} WHERE id = :id"),
                 {"to": to, "id": str(job_id), "reason": reason})
    audit.record(conn, tenant_id, actor, "job.transition",
                 {"job_id": str(job_id), "from": cur, "to": to, "attempt": attempt, "reason": reason,
                  **(extra or {})}, assessment_id)
    return cur
