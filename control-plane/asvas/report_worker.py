"""Report rendering worker (spec p.15: rendering runs as a separate asynchronous worker so large documents
never starve the orchestration loop). Renders in memory only — no temporary files on disk (spec p.16)."""

from __future__ import annotations

import io
import json
import logging
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import text

from asvas import audit, crypto
from asvas.canonical import sha256_hex
from asvas.db import row, tenant_tx
from asvas.reporting import build_report

log = logging.getLogger("asvas.reports")
STREAM, GROUP = "asvas:reports", "renderers"


def render_pdf(rep: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    st = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=st["BodyText"], fontSize=8.5, leading=11)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=7.5)
    p = lambda t, s=small: Paragraph(escape(str(t)), s)  # noqa: E731 - all text is escaped (untrusted data)
    a = rep["assessment"]
    story: list[Any] = [Paragraph(escape(f"Assessment report: {a['name']}"), st["Title"])]
    meta = [["Assessment", a["id"]], ["Status", a["status"]], ["Window", f"{a['started_at']} → {a['finished_at']}"],
            ["Authorization", f"{a['authorization']['reference']} by {a['authorization']['authorized_by']}"],
            ["Planner", f"{a['planner']['provider']} (live AI: {a['planner']['is_live_ai']})"],
            ["Audit chain", f"intact={rep['audit_chain']['ok']} ({rep['audit_chain']['events']} events)"],
            ["Generated", rep["generated_at"]]]
    if a["planner"]["note"]:
        meta.append(["Note", a["planner"]["note"]])
    t = Table([[p(k), p(v)] for k, v in meta], colWidths=[35 * mm, 135 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 6 * mm), Paragraph("Findings", st["Heading2"])]
    if not rep["findings"]:
        story.append(p("No findings were recorded by the implemented checks. This is not evidence of security."))
    for f in rep["findings"]:
        story.append(Paragraph(escape(f"[{f['severity'].upper()}] {f['title']}"), st["Heading4"]))
        rows_ = [["Asset", f["asset"]], ["Check / rule", f"{f['check_id']} / {f['rule_id']} {f['cwe'] or ''}"],
                 ["Verification", f"{f['verification_status']} (confidence {f['confidence']}); state {f['state']}"],
                 ["Observed", f["observed_behavior"]], ["Severity rationale", f["severity_rationale"]],
                 ["CVSS 4.0", f"{f['cvss']['base_score']} {f['cvss']['severity']} {f['cvss']['vector']} (base only)"
                  if f.get("cvss") else "not scored"],
                 ["Remediation", f["remediation"]],
                 ["Evidence", ", ".join(f"{e['id']} sha256:{e['sha256']}" for e in f["evidence"])],
                 ["Retests", "; ".join(f"{r['requested_at']}: {r['outcome']}" for r in f["retest_history"]) or "none"]]
        ft = Table([[p(k), p(v, mono if k == "Evidence" else small)] for k, v in rows_], colWidths=[35 * mm, 135 * mm])
        ft.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [ft, Spacer(1, 3 * mm)]
    story += [Paragraph("Limitations", st["Heading2"])] + [p(f"• {x}") for x in rep["limitations"]]
    SimpleDocTemplate(buf, pagesize=A4, title=f"ASVAS report {a['id']}", author="ASVAS",
                      leftMargin=18 * mm, rightMargin=18 * mm).build(story)
    return buf.getvalue()


def handle(engine, message: dict[str, Any]) -> str:
    tenant_id, report_id = message["tenant_id"], message["report_id"]
    with tenant_tx(tenant_id, engine) as conn:
        r = row(conn, "SELECT * FROM reports WHERE id = :id FOR UPDATE", id=report_id)
        if r is None or r["status"] != "QUEUED":
            return "ignored"  # idempotent: duplicates / already rendered
        conn.execute(text("UPDATE reports SET status='RENDERING' WHERE id=:id"), {"id": report_id})
    try:
        with tenant_tx(tenant_id, engine) as conn:
            rep = build_report(conn, tenant_id, r["assessment_id"])
        pdf = render_pdf(rep)
    except Exception as e:  # noqa: BLE001
        log.exception("render failed")
        with tenant_tx(tenant_id, engine) as conn:
            conn.execute(text("UPDATE reports SET status='FAILED', error=:e, completed_at=now() WHERE id=:id"),
                         {"e": f"{type(e).__name__}: {e}"[:500], "id": report_id})
            audit.record(conn, tenant_id, "system:report-worker", "report.failed", {"report_id": report_id},
                         r["assessment_id"])
        return "failed"
    digest = sha256_hex(pdf)
    with tenant_tx(tenant_id, engine) as conn:
        sealed = crypto.keyring().seal(pdf, crypto.report_aad(tenant_id, report_id))
        conn.execute(text("UPDATE reports SET status='READY', content=:c, sha256=:h, size_bytes=:n, completed_at=now(), "
                          "enc_alg=:alg, kek_id=:kid, dek_wrapped=:dek WHERE id=:id"),
                     {"c": sealed.ciphertext, "h": digest, "n": len(pdf), "id": report_id, "alg": sealed.alg,
                      "kid": sealed.kek_id, "dek": sealed.dek_wrapped})
        audit.record(conn, tenant_id, "system:report-worker", "report.rendered",
                     {"report_id": report_id, "format": "pdf", "sha256": digest, "bytes": len(pdf)}, r["assessment_id"])
    return "ready"


def run(stop_after: float | None = None) -> None:
    import time

    import redis

    from asvas.orchestration.bus import get_redis
    r = get_redis()
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError:
        pass
    consumer, started = f"render-{int(time.time())}", time.time()
    while stop_after is None or time.time() - started < stop_after:
        r.xautoclaim(STREAM, GROUP, consumer, min_idle_time=120000, start_id="0-0", count=5)
        for _, msgs in r.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=2, block=1000) or []:
            for mid, f in msgs:
                try:
                    handle(None, json.loads(f["message"]))
                except Exception:  # noqa: BLE001
                    log.exception("report message failed")
                r.xack(STREAM, GROUP, mid)
