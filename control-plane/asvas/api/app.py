"""FastAPI gateway (spec pp. 86-88): versioned REST, JWT auth, RBAC, schema validation, problem+json errors."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from asvas import audit, execgrpc, signatures
from asvas.api.schemas import (
    ApprovalDecision,
    ApproverKeyIn,
    AssessmentCreate,
    AssessmentUpdate,
    CancelRequest,
    DevLogin,
    EmergencyStop,
)
from asvas.audit import verify_chain
from asvas.auth import Principal, issue_token, lookup_user, require
from asvas.config import get_settings
from asvas.db import get_engine, row, rows, tenant_tx
from asvas.evidence import load_evidence
from asvas.orchestration import bus, engine
from asvas.orchestration.engine import Deps, OrchestrationError
from asvas.reporting import build_report, render_markdown
from asvas.statemachine import IllegalTransition
from asvas.tools import catalog


def problem(status: int, title: str, detail: Any = None, type_: str = "about:blank") -> JSONResponse:
    body = {"type": type_, "title": title, "status": status}
    if detail is not None:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


# Atomic Redis token bucket (spec p.86-87): capacity = per-minute limit, refilled continuously.
_BUCKET = """
local cap = tonumber(ARGV[1]); local rate = cap / 60000.0; local now = tonumber(ARGV[2])
local b = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(b[1]) or cap; local ts = tonumber(b[2]) or now
tokens = math.min(cap, tokens + (now - ts) * rate)
local ok = 0
if tokens >= 1 then tokens = tokens - 1; ok = 1 end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], 120000)
return {ok, math.ceil((1 - tokens) / rate / 1000)}
"""


def token_bucket(r, key: str, per_minute: int) -> tuple[bool, int]:
    ok, retry = r.eval(_BUCKET, 1, key, per_minute, int(time.time() * 1000))
    return bool(ok), max(1, int(retry))


def create_app(deps: Deps | None = None) -> FastAPI:
    s = get_settings()
    app = FastAPI(title="ASVAS Control Plane", version="0.1.0-m1",
                  description="Milestone-1 development build. Not production-ready.")
    app.state.deps = deps or Deps()
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type"])

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, e: StarletteHTTPException):
        resp = problem(e.status_code, str(e.detail))
        for k, v in (getattr(e, "headers", None) or {}).items():
            resp.headers[k] = v
        return resp

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError):
        errs = [{"loc": list(x["loc"]), "msg": x["msg"], "type": x["type"]} for x in e.errors()]
        return problem(422, "Request validation failed", errs)

    @app.exception_handler(OrchestrationError)
    async def _orch(_: Request, e: OrchestrationError):
        return problem(e.status, str(e))

    @app.exception_handler(IllegalTransition)
    async def _ill(_: Request, e: IllegalTransition):
        return problem(409, str(e))

    def deps_of(request: Request) -> Deps:
        return request.app.state.deps

    def rate_limited(request: Request, p: Principal = Depends(require("viewer"))) -> Principal:
        allowed, retry = token_bucket(deps_of(request).r, f"asvas:tb:{p.tenant_id}", s.rate_limit_per_minute)
        if not allowed:
            raise HTTPException(429, f"tenant rate limit exceeded ({s.rate_limit_per_minute} requests/minute)",
                                headers={"Retry-After": str(retry)})
        return p

    def role(name: str):
        def dep(p: Principal = Depends(rate_limited)) -> Principal:
            if not p.has(name):
                raise HTTPException(403, f"requires role '{name}' (you are '{p.role}')")
            return p
        return dep

    api = APIRouter(prefix="/api/v1")

    # ------------------------------------------------------------------ public / auth
    @api.get("/health")
    def health(request: Request):
        d = deps_of(request)
        out: dict[str, Any] = {}
        try:
            with get_engine().connect() as c:
                c.execute(text("SELECT 1"))
            out["database"] = "ok"
        except Exception as e:  # noqa: BLE001
            out["database"] = f"error: {type(e).__name__}"
        try:
            d.r.ping()
            out["redis"] = "ok"
        except Exception as e:  # noqa: BLE001
            out["redis"] = f"error: {type(e).__name__}"
        out["opa"] = d.policy.health()
        out["env"] = s.env
        return out

    if s.env == "development":
        from asvas.seed import DEV_USERS

        @api.get("/auth/dev-users")
        def dev_users():
            return [{"email": u[0], "display_name": u[1], "role": u[2], "tenant": u[3]} for u in DEV_USERS]

        @api.post("/auth/dev-login")
        def dev_login(body: DevLogin):
            u = lookup_user(email=body.email)
            if not u or not u["active"]:
                raise HTTPException(401, "unknown or inactive user")
            with tenant_tx(u["tenant_id"]) as conn:
                audit.record(conn, u["tenant_id"], f"user:{u['id']}", "auth.dev_login", {"email": u["email"]})
            return {"access_token": issue_token(u["id"], u["tenant_id"], u["role"]), "token_type": "bearer",
                    "dev_only": True}

    @api.get("/me")
    def me(p: Principal = Depends(rate_limited)):
        return {"user_id": str(p.user_id), "tenant_id": str(p.tenant_id), "email": p.email,
                "display_name": p.display_name, "role": p.role}

    @api.get("/tools")
    def tools(_: Principal = Depends(rate_limited)):
        return catalog()

    # ------------------------------------------------------------------ assessments
    @api.get("/assessments")
    def list_assessments(p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            return rows(conn, "SELECT a.id, a.name, a.status, a.created_at, a.updated_at, a.started_at, a.finished_at, "
                              "a.provider_name, a.provider_is_live_ai, a.failure_reason, "
                              "(SELECT count(*) FROM findings f WHERE f.assessment_id = a.id) AS findings, "
                              "(SELECT count(*) FROM approvals x WHERE x.assessment_id = a.id AND x.status='PENDING') "
                              "AS pending_approvals FROM assessments a ORDER BY a.created_at DESC LIMIT 200")

    @api.post("/assessments", status_code=201)
    def create_assessment(body: AssessmentCreate, p: Principal = Depends(role("operator"))):
        with tenant_tx(p.tenant_id) as conn:
            aid = conn.execute(text(
                "INSERT INTO assessments (tenant_id, name, description, status, scope, testing_policy, created_by) "
                "VALUES (:t,:n,:d,'DRAFT',CAST(:s AS jsonb),CAST(:pol AS jsonb),:u) RETURNING id"),
                {"t": str(p.tenant_id), "n": body.name, "d": body.description,
                 "s": body.scope.model_dump_json(), "pol": body.testing_policy.model_dump_json(),
                 "u": str(p.user_id)}).scalar()
            audit.record(conn, p.tenant_id, p.actor, "assessment.created",
                         {"name": body.name, "scope": body.scope.model_dump(mode="json"),
                          "testing_policy": body.testing_policy.model_dump(mode="json")}, aid)
            return row(conn, "SELECT * FROM assessments WHERE id = :id", id=str(aid))

    def _get(conn, aid: uuid.UUID) -> dict:
        a = row(conn, "SELECT * FROM assessments WHERE id = :id", id=str(aid))
        if a is None:
            raise HTTPException(404, "assessment not found")
        a.pop("frozen_scope_doc", None)
        return a

    @api.get("/assessments/{aid}")
    def get_assessment(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            a = _get(conn, aid)
            a["job_counts"] = {r["status"]: r["n"] for r in rows(
                conn, "SELECT status, count(*) n FROM jobs WHERE assessment_id = :a GROUP BY status", a=str(aid))}
            return a

    @api.patch("/assessments/{aid}")
    def update_assessment(aid: uuid.UUID, body: AssessmentUpdate, p: Principal = Depends(role("operator"))):
        with tenant_tx(p.tenant_id) as conn:
            a = row(conn, "SELECT status FROM assessments WHERE id = :id FOR UPDATE", id=str(aid))
            if a is None:
                raise HTTPException(404, "assessment not found")
            if a["status"] != "DRAFT":
                raise HTTPException(409, "scope and policy are immutable once an assessment has started")
            changes = body.model_dump(exclude_none=True, mode="json")
            for k, col in (("name", "name"), ("description", "description")):
                if k in changes:
                    conn.execute(text(f"UPDATE assessments SET {col} = :v WHERE id = :id"), {"v": changes[k], "id": str(aid)})
            for k in ("scope", "testing_policy"):
                if k in changes:
                    conn.execute(text(f"UPDATE assessments SET {k} = CAST(:v AS jsonb) WHERE id = :id"),
                                 {"v": json.dumps(changes[k]), "id": str(aid)})
            conn.execute(text("UPDATE assessments SET updated_at = now(), version = version + 1 WHERE id = :id"),
                         {"id": str(aid)})
            audit.record(conn, p.tenant_id, p.actor, "assessment.updated", changes, aid)
            return _get(conn, aid)

    @api.post("/assessments/{aid}/start", status_code=202)
    def start(aid: uuid.UUID, request: Request, p: Principal = Depends(role("operator"))):
        res = engine.start_assessment(deps_of(request), p.tenant_id, aid, p.user_id)
        return {**res, "status_url": f"/api/v1/assessments/{aid}"}

    @api.post("/assessments/{aid}/cancel", status_code=202)
    def cancel(aid: uuid.UUID, body: CancelRequest, request: Request, p: Principal = Depends(role("operator"))):
        return {"assessment_id": str(aid),
                "status": engine.cancel_assessment(deps_of(request), p.tenant_id, aid, p.actor, body.reason)}

    @api.get("/assessments/{aid}/jobs")
    def jobs(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            out = rows(conn, "SELECT * FROM jobs WHERE assessment_id = :a ORDER BY created_at", a=str(aid))
            res = {r["job_id"]: r for r in rows(conn, "SELECT r.* FROM job_results r JOIN jobs j ON j.id = r.job_id "
                                                      "WHERE j.assessment_id = :a ORDER BY r.attempt", a=str(aid))}
            for j in out:
                j["last_result"] = res.get(j["id"])
            return out

    @api.get("/assessments/{aid}/plan")
    def plan(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            return rows(conn, "SELECT n.*, j.status AS job_status FROM plan_nodes n LEFT JOIN jobs j "
                              "ON j.id::text = n.data->>'job_id' WHERE n.assessment_id = :a ORDER BY n.round, n.created_at",
                        a=str(aid))

    @api.get("/assessments/{aid}/timeline")
    def timeline(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            return rows(conn, "SELECT id, actor, event_type, data, created_at, hash FROM audit_events "
                              "WHERE assessment_id = :a ORDER BY id", a=str(aid))

    @api.get("/assessments/{aid}/events")
    def events(aid: uuid.UUID, request: Request, p: Principal = Depends(rate_limited),
               after: int = Query(0, ge=0), max_seconds: int = Query(600, ge=1, le=3600)):
        """Server-sent events of the assessment's audit events (live status / timeline). Read-only.

        Authenticated with the normal bearer header (clients use fetch streaming, so tokens never go in URLs).
        """
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
        last_hdr = request.headers.get("last-event-id")
        start_after = int(last_hdr) if last_hdr and last_hdr.isdigit() else after

        def gen():
            last, quiet, started, beat = start_after, 0.0, time.time(), time.time()
            yield "retry: 3000\n\n"
            while time.time() - started < max_seconds:
                with tenant_tx(p.tenant_id) as conn:
                    evs = rows(conn, "SELECT id, actor, event_type, data, created_at FROM audit_events "
                                     "WHERE assessment_id = :a AND id > :l ORDER BY id LIMIT 200", a=str(aid), l=last)
                    st = row(conn, "SELECT status FROM assessments WHERE id = :a", a=str(aid))
                for e in evs:
                    last = e["id"]
                    yield f"id: {e['id']}\nevent: audit\ndata: {json.dumps(e, default=str)}\n\n"
                if evs:
                    quiet = 0.0
                    yield f"event: status\ndata: {json.dumps({'status': st['status'] if st else None})}\n\n"
                elif st and st["status"] in ("COMPLETED", "FAILED", "CANCELLED", "DRAFT"):
                    quiet += 1
                    if quiet >= 5:
                        yield f"event: end\ndata: {json.dumps({'status': st['status']})}\n\n"
                        return
                if time.time() - beat > 15:
                    beat = time.time()
                    yield ": keep-alive\n\n"
                time.sleep(1)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @api.get("/assessments/{aid}/findings")
    def findings(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            out = rows(conn, "SELECT f.*, s.identifier AS asset FROM findings f JOIN assets s ON s.id = f.asset_id "
                             "WHERE f.assessment_id = :a ORDER BY f.created_at", a=str(aid))
            for f in out:
                f["retests"] = rows(conn, "SELECT * FROM finding_retests WHERE finding_id = :f ORDER BY created_at",
                                    f=str(f["id"]))
            return out

    @api.get("/assessments/{aid}/assets")
    def assets(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            return {"assets": rows(conn, "SELECT * FROM assets WHERE assessment_id = :a ORDER BY kind, identifier", a=str(aid)),
                    "relations": rows(conn, "SELECT * FROM asset_relations WHERE assessment_id = :a", a=str(aid))}

    @api.get("/assessments/{aid}/graph")
    def graph(aid: uuid.UUID, request: Request, p: Principal = Depends(rate_limited)):
        """Topology from the graph store (Neo4j). Tenant id comes from the authenticated principal only."""
        from asvas.graphstore import GraphUnavailable
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)  # 404 for other tenants' assessments before touching the graph store
        try:
            return deps_of(request).graph_store.assessment_graph(str(p.tenant_id), str(aid))
        except GraphUnavailable as e:
            raise HTTPException(503, f"graph store unavailable: {e}") from e

    @api.get("/assessments/{aid}/report")
    def report(aid: uuid.UUID, format: str = Query("json", pattern="^(json|md)$"), p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            rep = build_report(conn, p.tenant_id, aid)
            if rep is None:
                raise HTTPException(404, "assessment not found")
            audit.record(conn, p.tenant_id, p.actor, "report.generated", {"format": format}, aid)
        if format == "md":
            return PlainTextResponse(render_markdown(rep), media_type="text/markdown")
        return rep

    @api.post("/assessments/{aid}/reports", status_code=202)
    def request_report(aid: uuid.UUID, request: Request, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            rid = conn.execute(text("INSERT INTO reports (tenant_id, assessment_id, requested_by, format, status) "
                                    "VALUES (:t,:a,:u,'pdf','QUEUED') RETURNING id"),
                               {"t": str(p.tenant_id), "a": str(aid), "u": str(p.user_id)}).scalar()
            audit.record(conn, p.tenant_id, p.actor, "report.requested", {"report_id": str(rid), "format": "pdf"}, aid)
        deps_of(request).r.xadd("asvas:reports", {"message": json.dumps(
            {"tenant_id": str(p.tenant_id), "report_id": str(rid)})}, maxlen=10000, approximate=True)
        return {"report_id": str(rid), "status": "QUEUED", "status_url": f"/api/v1/reports/{rid}"}

    @api.get("/assessments/{aid}/reports")
    def list_reports(aid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            _get(conn, aid)
            return rows(conn, "SELECT id, format, status, sha256, size_bytes, error, created_at, completed_at "
                              "FROM reports WHERE assessment_id = :a ORDER BY created_at DESC", a=str(aid))

    @api.get("/reports/{rid}")
    def get_report(rid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            r = row(conn, "SELECT id, assessment_id, format, status, sha256, size_bytes, error, created_at, completed_at "
                          "FROM reports WHERE id = :id", id=str(rid))
        if r is None:
            raise HTTPException(404, "report not found")
        return r

    @api.get("/reports/{rid}/download")
    def download_report(rid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            r = row(conn, "SELECT status, content, sha256, assessment_id, enc_alg, kek_id, dek_wrapped "
                          "FROM reports WHERE id = :id", id=str(rid))
            if r is None:
                raise HTTPException(404, "report not found")
            if r["status"] != "READY":
                raise HTTPException(409, f"report is {r['status']}")
            audit.record(conn, p.tenant_id, p.actor, "report.downloaded", {"report_id": str(rid)}, r["assessment_id"])
        from asvas import crypto
        from asvas.canonical import sha256_hex
        pdf = bytes(r["content"])
        if r["enc_alg"]:
            pdf = crypto.keyring().open(pdf, bytes(r["dek_wrapped"]), r["kek_id"], crypto.report_aad(p.tenant_id, rid))
        if sha256_hex(pdf) != r["sha256"]:
            raise HTTPException(500, "stored report failed its integrity check")
        return Response(pdf, media_type="application/pdf", headers={
            "X-Content-SHA256": r["sha256"], "Content-Disposition": f'attachment; filename="asvas-report-{rid}.pdf"',
            "Cache-Control": "no-store"})

    # ------------------------------------------------------------------ approvals
    @api.get("/approvals")
    def approvals(status: str | None = Query(None, pattern="^(PENDING|APPROVED|REJECTED|EXPIRED|INVALIDATED|CONSUMED)$"),
                  p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            q = ("SELECT x.id, x.tenant_id, x.assessment_id, x.job_id, x.binding_hash, x.binding_summary, x.status, "
                 "x.requested_by, x.decided_by, x.decided_at, x.expires_at, x.reason, x.created_at, x.signer_key_id, "
                 "x.signed_message, floor(extract(epoch FROM x.expires_at))::bigint AS expires_unix, "
                 "a.name AS assessment_name, (x.expires_at <= now()) AS is_expired FROM approvals x "
                 "JOIN assessments a ON a.id = x.assessment_id")
            if status:
                return rows(conn, q + " WHERE x.status = :s ORDER BY x.created_at DESC LIMIT 200", s=status)
            return rows(conn, q + " ORDER BY x.created_at DESC LIMIT 200")

    @api.post("/approvals/{apid}/decision")
    def decide(apid: uuid.UUID, body: ApprovalDecision, request: Request, p: Principal = Depends(role("approver"))):
        return engine.decide_approval(deps_of(request), p.tenant_id, apid, p.user_id, p.role, body.decision,
                                      body.binding_hash, body.reason, body.key_id, body.signature)

    @api.get("/jobs/{jid}/execution-log")
    def execution_log(jid: uuid.UUID, p: Principal = Depends(rate_limited)):
        """Transient operational log for a job (DA-14: wiped after the retention period; evidence is kept)."""
        with tenant_tx(p.tenant_id) as conn:
            return rows(conn, "SELECT id, attempt, event, detail, created_at FROM execution_log WHERE job_id = :j "
                              "ORDER BY id", j=str(jid))

    @api.get("/approver-keys")
    def my_keys(p: Principal = Depends(role("approver"))):
        with tenant_tx(p.tenant_id) as conn:
            return rows(conn, "SELECT id, alg, fingerprint, label, created_at, revoked_at FROM approver_keys "
                              "WHERE user_id = :u ORDER BY created_at DESC", u=str(p.user_id))

    @api.post("/approver-keys", status_code=201)
    def register_key(body: ApproverKeyIn, p: Principal = Depends(role("approver"))):
        try:
            raw = signatures.parse_public_key(body.public_key)
        except ValueError as e:
            raise HTTPException(422, f"invalid Ed25519 public key: {e}") from e
        fp = signatures.fingerprint(raw)
        with tenant_tx(p.tenant_id) as conn:
            if row(conn, "SELECT 1 AS x FROM approver_keys WHERE fingerprint = :f", f=fp):
                raise HTTPException(409, "key already registered")
            kid = conn.execute(text(
                "INSERT INTO approver_keys (tenant_id, user_id, alg, public_key, fingerprint, label) "
                "VALUES (:t, :u, 'Ed25519', :pk, :f, :l) RETURNING id"),
                {"t": str(p.tenant_id), "u": str(p.user_id), "pk": raw, "f": fp, "l": body.label}).scalar()
            audit.record(conn, p.tenant_id, f"user:{p.user_id}", "approver_key.registered",
                         {"key_id": str(kid), "fingerprint": fp, "alg": "Ed25519", "label": body.label})
        return {"id": str(kid), "fingerprint": fp, "alg": "Ed25519"}

    @api.post("/approver-keys/{kid}/revoke")
    def revoke_key(kid: uuid.UUID, p: Principal = Depends(role("approver"))):
        with tenant_tx(p.tenant_id) as conn:
            k = row(conn, "SELECT * FROM approver_keys WHERE id = :id", id=str(kid))
            if k is None or (str(k["user_id"]) != str(p.user_id) and p.role != "admin"):
                raise HTTPException(404, "key not found")
            if k["revoked_at"] is None:
                conn.execute(text("UPDATE approver_keys SET revoked_at = now() WHERE id = :id"), {"id": str(kid)})
                audit.record(conn, p.tenant_id, f"user:{p.user_id}", "approver_key.revoked",
                             {"key_id": str(kid), "fingerprint": k["fingerprint"]})
        return {"id": str(kid), "revoked": True}

    # ------------------------------------------------------------------ findings / evidence
    @api.post("/findings/{fid}/retest", status_code=202)
    def retest(fid: uuid.UUID, request: Request, p: Principal = Depends(role("operator"))):
        return engine.request_retest(deps_of(request), p.tenant_id, fid, p.user_id)

    @api.get("/evidence/{eid}")
    def evidence(eid: uuid.UUID, p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            e = load_evidence(conn, eid)
            if e is None:
                raise HTTPException(404, "evidence not found")
            return e

    # ------------------------------------------------------------------ audit / system
    @api.get("/audit")
    def audit_log(limit: int = Query(200, ge=1, le=1000), p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            return rows(conn, "SELECT id, assessment_id, actor, event_type, data, created_at, prev_hash, hash "
                              "FROM audit_events ORDER BY id DESC LIMIT :n", n=limit)

    @api.get("/audit/verify")
    def audit_verify(p: Principal = Depends(rate_limited)):
        with tenant_tx(p.tenant_id) as conn:
            return verify_chain(conn, p.tenant_id)

    @api.get("/system/status")
    def system_status(request: Request, p: Principal = Depends(rate_limited)):
        d = deps_of(request)
        now = time.time()
        workers = []
        try:
            for wid, raw in d.r.hgetall(bus.WORKERS).items():
                w = json.loads(raw)
                w["worker_id"] = wid
                w["stale"] = now - w.get("heartbeat_unix", 0) > s.worker_stale_seconds
                w["grpc"] = execgrpc.probe(w["grpc_addr"]) if w.get("grpc_addr") and not w["stale"] else \
                    {"reachable": False, "detail": "executor did not advertise an mTLS endpoint"}
                workers.append(w)
            redis_ok = True
        except Exception:  # noqa: BLE001
            redis_ok = False
        with tenant_tx(p.tenant_id) as conn:
            ctl = row(conn, "SELECT * FROM tenant_controls WHERE tenant_id = :t", t=str(p.tenant_id))
        return {"workers": workers, "redis_ok": redis_ok, "policy_engine": d.policy.health(),
                "graph_store": d.graph_store.health(),
                "emergency_stop": bool(ctl and ctl["emergency_stop"]), "emergency_stop_detail": ctl,
                "planner": {"provider": s.model_provider,
                            "is_live_ai": s.model_provider != "deterministic-test"},
                "unavailable_features": [
                    {"feature": "Firecracker microVM isolation", "requirement": "PO-10", "reason": "needs KVM host"},
                    {"feature": "eBPF syscall monitor", "requirement": "PO-12", "reason": "needs eBPF-capable host"},
                    {"feature": "Qdrant long-term memory", "requirement": "DA-04", "reason": "planned M3"},
                    {"feature": "OIDC SSO / MFA", "requirement": "CP-07", "reason": "planned M3"},
                    {"feature": "Compliance mapping", "requirement": "DA-12", "reason": "planned M4"},
                ]}

    @api.get("/compliance/controls")
    def compliance_controls(request: Request, p: Principal = Depends(rate_limited)):
        """UI-04: read-only control status for auditors (and admins). Computed live; not a certification."""
        if p.role not in ("auditor", "admin"):
            raise HTTPException(403, f"requires role 'auditor' or 'admin' (you are '{p.role}')")
        from asvas import compliance
        health = deps_of(request).policy.health()
        with tenant_tx(p.tenant_id) as conn:
            return {"generated_at": time.time(), "tenant_id": str(p.tenant_id),
                    "controls": compliance.controls(conn, p.tenant_id, health)}

    @api.get("/system/policy")
    def policy_source(p: Principal = Depends(role("operator"))):
        """Advanced view (UI-03): the Rego policy currently on disk, read-only. Editing policy is not exposed."""
        from asvas import compliance
        base = compliance.policy_base()
        return {"files": [{"path": str(f.relative_to(base)), "sha256": h, "source": f.read_text()}
                          for f, h in compliance.policy_files()]}

    @api.post("/system/emergency-stop")
    def estop(body: EmergencyStop, request: Request, p: Principal = Depends(role("admin"))):
        return engine.emergency_stop(deps_of(request), p.tenant_id, p.user_id, body.reason)

    @api.post("/system/emergency-stop/reset")
    def estop_reset(request: Request, p: Principal = Depends(role("admin"))):
        engine.reset_emergency_stop(deps_of(request), p.tenant_id, p.user_id)
        return {"emergency_stop": False}

    app.include_router(api)
    return app
