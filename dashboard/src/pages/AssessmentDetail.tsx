import { useState } from "react";
import { useParams } from "react-router";
import { api, apiBlob, ApiError, type Approval, type Assessment, type AuditEvent, type Finding, type Job, type PlanNode } from "../api";
import { can, useMe } from "../App";
import { useResource } from "../hooks";
import { Badge, PlannerLabel, StateView, When } from "../ui";
import { ApprovalCard } from "./Approvals";
import { PlanGraph } from "./PlanGraph";
import { Topology } from "./Topology";

const ACTIVE = new Set(["PLANNING", "RUNNING", "AWAITING_APPROVAL", "REPORTING", "CANCELLING"]);
const TABS = ["Overview", "Plan graph", "Jobs", "Findings", "Timeline", "Assets", "Report"] as const;

export function AssessmentDetailPage() {
  const { id } = useParams();
  const r = useResource<Assessment>(`/assessments/${id}`, 2000);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  return (
    <StateView r={r}>
      {(a) => (
        <section>
          <div className="pagehead">
            <div><h1>{a.name}</h1><div className="small muted">{a.id}</div></div>
            <Controls a={a} reload={r.reload} />
          </div>
          <div className="statusline">
            <Badge v={a.status} /> <PlannerLabel name={a.provider_name} live={a.provider_is_live_ai} />
            {ACTIVE.has(a.status) && <span className="small muted"><span className="spinner" /> live — refreshing every 2 s</span>}
            {a.failure_reason && <span className="bad">Failure: {a.failure_reason}</span>}
          </div>
          <div className="tabs" role="tablist">
            {TABS.map((t) => <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>{t}</button>)}
          </div>
          {tab === "Overview" && <Overview a={a} />}
          {tab === "Plan graph" && <PlanTab id={a.id} active={ACTIVE.has(a.status)} />}
          {tab === "Jobs" && <JobsTab id={a.id} active={ACTIVE.has(a.status)} />}
          {tab === "Findings" && <FindingsTab a={a} />}
          {tab === "Timeline" && <TimelineTab id={a.id} active={ACTIVE.has(a.status)} />}
          {tab === "Assets" && <AssetsTab id={a.id} />}
          {tab === "Report" && <ReportTab a={a} />}
        </section>
      )}
    </StateView>
  );
}

function Controls({ a, reload }: { a: Assessment; reload: () => void }) {
  const me = useMe();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [confirm, setConfirm] = useState(false);
  if (!can(me, "operator")) return <span className="small muted">Read-only ({me.role})</span>;
  const act = async (path: string, body?: unknown) => {
    setBusy(true); setErr(undefined);
    try { await api(path, { method: "POST", body }); reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
    finally { setBusy(false); setConfirm(false); }
  };
  return (
    <div className="actions">
      {a.status === "DRAFT" && <button className="btn primary" disabled={busy} onClick={() => act(`/assessments/${a.id}/start`)}>Start assessment</button>}
      {(a.status === "DRAFT" || ACTIVE.has(a.status)) && a.status !== "CANCELLING" && (
        confirm
          ? <><span className="small">Cancel and kill running workers?</span>
              <button className="btn danger" disabled={busy} onClick={() => act(`/assessments/${a.id}/cancel`, { reason: "cancelled from dashboard" })}>Yes, cancel</button>
              <button className="btn" onClick={() => setConfirm(false)}>No</button></>
          : <button className="btn danger" disabled={busy} onClick={() => setConfirm(true)}>Cancel</button>
      )}
      {err && <span className="bad small" role="alert">{err}</span>}
    </div>
  );
}

function Overview({ a }: { a: Assessment }) {
  const s = a.scope!, p = a.testing_policy!;
  return (
    <div className="grid two">
      <div className="card"><h3>Scope</h3>
        <dl className="kv">
          <dt>Targets</dt><dd>{s.targets.map((t) => <div key={t.host}><code>{t.host}</code> ports {t.ports.join(", ")} ({t.schemes.join("/")})</div>)}</dd>
          <dt>Allowed CIDRs</dt><dd><code>{s.allowed_cidrs.join(", ")}</code></dd>
          <dt>Excluded</dt><dd>{s.excluded_cidrs.length ? <code>{s.excluded_cidrs.join(", ")}</code> : <span className="muted">none</span>}</dd>
          <dt>Authorization</dt><dd>{s.authorization.reference} by {s.authorization.authorized_by}<div className="small muted">{s.authorization.statement}</div>
            <div className="small"><When t={s.authorization.valid_from} /> → <When t={s.authorization.valid_until} /></div></dd>
        </dl>
      </div>
      <div className="card"><h3>Policy &amp; budgets</h3>
        <dl className="kv">
          <dt>Tools</dt><dd>{p.allowed_tools.join(", ")}</dd>
          <dt>Approval needed for</dt><dd>{p.approval_required_risk_tiers.join(", ")} risk</dd>
          <dt>Requests</dt><dd>{a.requests_used} / {p.max_total_requests} (≤{p.max_requests_per_second}/s)</dd>
          <dt>Model tokens</dt><dd>{a.tokens_used} / {p.max_tokens}</dd>
          <dt>Planning rounds</dt><dd>{a.planning_rounds} / {p.max_planning_rounds} (depth ≤ {p.max_plan_depth})</dd>
          <dt>Job timeout</dt><dd>{p.job_timeout_seconds} s, ≤{p.max_attempts} attempts, concurrency {p.max_concurrency}</dd>
          <dt>Wall clock</dt><dd>{p.max_wall_clock_minutes} min · started <When t={a.started_at} /> · finished <When t={a.finished_at} /></dd>
          <dt>Jobs</dt><dd>{Object.entries(a.job_counts ?? {}).map(([k, v]) => <span key={k}><Badge v={k} /> {v} </span>)}</dd>
        </dl>
      </div>
      <PendingApprovals id={a.id} />
    </div>
  );
}

function PendingApprovals({ id }: { id: string }) {
  const r = useResource<Approval[]>("/approvals?status=PENDING", 3000);
  const mine = (r.data ?? []).filter((x) => x.assessment_id === id);
  if (!mine.length) return null;
  return <div className="card span2"><h3>Waiting for approval</h3><div className="grid">{mine.map((a) => <ApprovalCard key={a.id} a={a} onDone={r.reload} />)}</div></div>;
}

function PlanTab({ id, active }: { id: string; active: boolean }) {
  const r = useResource<PlanNode[]>(`/assessments/${id}/plan`, active ? 2000 : 0);
  return <StateView r={r} empty={(d) => d.length === 0} emptyText="No plan yet (assessment not started or planning in progress).">
    {(nodes) => <PlanGraph nodes={nodes} />}
  </StateView>;
}

function JobsTab({ id, active }: { id: string; active: boolean }) {
  const r = useResource<Job[]>(`/assessments/${id}/jobs`, active ? 2000 : 0);
  return <StateView r={r} empty={(d) => d.length === 0} emptyText="No jobs.">
    {(jobs) => <div className="tablewrap"><table>
      <thead><tr><th>Tool</th><th>Target</th><th>Params</th><th>Risk</th><th>Status</th><th>Attempt</th><th>Policy</th><th>Executor</th></tr></thead>
      <tbody>{jobs.map((j) => <tr key={j.id}>
        <td>{j.tool_id}{j.retest_of_finding && <div className="small muted">retest</div>}</td>
        <td><code>{j.target.scheme}://{j.target.host}:{j.target.port}</code></td>
        <td><code className="small">{JSON.stringify(j.params)}</code></td>
        <td><Badge v={j.risk_tier} /></td>
        <td><Badge v={j.status} />{j.error && <div className="small bad">{j.error}</div>}</td>
        <td>{j.attempt}/{j.max_attempts}</td>
        <td className="small">{j.policy_decision ? (j.policy_decision.deny_reasons.length ? j.policy_decision.deny_reasons.join("; ") :
          j.policy_decision.require_approval ? "approval required" : "allowed") : "—"}</td>
        <td className="small">{j.last_result ? <>{j.last_result.backend}<div className="muted">{j.last_result.egress_mode}</div></> : "—"}</td>
      </tr>)}</tbody>
    </table></div>}
  </StateView>;
}

function FindingsTab({ a }: { a: Assessment }) {
  const me = useMe();
  const r = useResource<Finding[]>(`/assessments/${a.id}/findings`, ACTIVE.has(a.status) ? 3000 : 0);
  const [ev, setEv] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const retest = async (fid: string) => {
    setMsg(undefined);
    try { const res = await api<{ job_status: string }>(`/findings/${fid}/retest`, { method: "POST" }); setMsg(`Retest job ${res.job_status}`); r.reload(); }
    catch (e) { setMsg(e instanceof ApiError ? e.title : String(e)); }
  };
  return <>
    {msg && <div className="banner">{msg}</div>}
    <StateView r={r} empty={(d) => d.length === 0}
      emptyText={a.status === "COMPLETED" ? "No findings were produced by the implemented checks. This is not evidence that the targets are secure." : "No findings yet."}>
      {(fs) => <div className="grid">{fs.map((f) => (
        <div className="card finding" key={f.id}>
          <div className="cardhead"><Badge v={f.severity} /> <b>{f.title}</b> <Badge v={f.verification_status} /> <Badge v={f.state} /></div>
          <dl className="kv">
            <dt>Asset</dt><dd><code>{f.asset}</code></dd>
            <dt>Check</dt><dd>{f.check_id} / {f.rule_id} {f.cwe && <span className="muted">· {f.cwe}</span>}</dd>
            <dt>Observed</dt><dd>{f.observed_behavior}</dd>
            <dt>Severity rationale</dt><dd>{f.severity_rationale} <span className="muted">(confidence {f.confidence})</span></dd>
            <dt>CVSS 4.0</dt><dd>{f.cvss_vector ? <><b>{Number(f.cvss_score).toFixed(1)}</b> <Badge v={f.cvss_severity} /> <code className="small">{f.cvss_vector}</code>
              <div className="small muted">Base metrics only (CVSS-B), rule-assigned; not exploitation-verified.</div></> : <span className="muted">not scored for this rule</span>}</dd>
            <dt>Remediation</dt><dd>{f.remediation}</dd>
            <dt>Recorded</dt><dd><When t={f.created_at} /></dd>
            <dt>Evidence</dt><dd>{f.evidence_ids.map((e) => <button key={e} className="link" onClick={() => setEv(e)}>{e.slice(0, 8)}…</button>)}</dd>
            <dt>Retests</dt><dd>{f.retests.length ? f.retests.map((t) => <div key={t.id}><Badge v={t.outcome} /> <When t={t.created_at} /></div>) : <span className="muted">none</span>}</dd>
          </dl>
          {f.verification_status === "suspected" && <p className="small warn">Suspected only — indicated by untrusted target text, not verified.</p>}
          {can(me, "operator") && <button className="btn" onClick={() => retest(f.id)}>Request retest</button>}
        </div>))}</div>}
    </StateView>
    {ev && <EvidenceDrawer id={ev} onClose={() => setEv(undefined)} />}
  </>;
}

function EvidenceDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const r = useResource<{ sha256: string; integrity_ok: boolean; created_at: string; job_id: string; attempt: number; content: unknown }>(`/evidence/${id}`);
  return (
    <div className="drawer" role="dialog" aria-label="Evidence">
      <div className="drawerhead"><b>Evidence {id}</b><button className="link" onClick={onClose}>Close</button></div>
      <StateView r={r}>{(e) => <>
        <dl className="kv">
          <dt>SHA-256</dt><dd><code className="hash">{e.sha256}</code> {e.integrity_ok ? <Badge v="SUCCEEDED" /> : <span className="bad">HASH MISMATCH</span>}</dd>
          <dt>Job / attempt</dt><dd><code>{e.job_id}</code> / {e.attempt}</dd>
          <dt>Captured</dt><dd><When t={e.created_at} /></dd>
        </dl>
        <p className="small warn">Target-controlled content below is untrusted data and is displayed as text only.</p>
        <pre className="evidence">{JSON.stringify(e.content, null, 2)}</pre>
      </>}</StateView>
    </div>
  );
}

function TimelineTab({ id, active }: { id: string; active: boolean }) {
  const r = useResource<AuditEvent[]>(`/assessments/${id}/timeline`, active ? 2000 : 0);
  return <StateView r={r} empty={(d) => d.length === 0}>
    {(evs) => <ol className="timeline">{evs.map((e) => (
      <li key={e.id}><When t={e.created_at} /> <b>{e.event_type}</b> <span className="muted small">{e.actor}</span>
        <details><summary className="small">details</summary><pre>{JSON.stringify(e.data, null, 2)}</pre><div className="small muted">hash {e.hash}</div></details>
      </li>))}</ol>}
  </StateView>;
}

function AssetsTab({ id }: { id: string }) {
  const r = useResource<{ assets: { id: string; kind: string; identifier: string; attributes: Record<string, unknown>; last_seen: string }[]; relations: { src_asset: string; dst_asset: string; relation: string }[] }>(`/assessments/${id}/assets`);
  return <StateView r={r} empty={(d) => d.assets.length === 0} emptyText="No assets observed yet.">
    {(d) => <>
      <h3>Topology (graph store)</h3>
      <Topology id={id} />
      <h3>Assets (PostgreSQL — source of truth)</h3>
      <div className="tablewrap"><table><thead><tr><th>Kind</th><th>Identifier</th><th>Attributes (untrusted)</th><th>Last seen</th><th>Relations</th></tr></thead>
        <tbody>{d.assets.map((x) => <tr key={x.id}><td>{x.kind}</td><td><code>{x.identifier}</code></td><td><code className="small">{JSON.stringify(x.attributes)}</code></td>
          <td><When t={x.last_seen} /></td>
          <td className="small">{d.relations.filter((rel) => rel.src_asset === x.id).map((rel) => `${rel.relation} → ${d.assets.find((y) => y.id === rel.dst_asset)?.identifier}`).join(", ")}</td></tr>)}</tbody>
      </table></div></>}
  </StateView>;
}

interface ReportDoc { id: string; status: string; sha256: string | null; size_bytes: number | null; error: string | null; created_at: string; completed_at: string | null }

function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const el = document.createElement("a");
  el.href = url; el.download = name; el.click();
  URL.revokeObjectURL(url);
}

function ReportTab({ a }: { a: Assessment }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const docs = useResource<ReportDoc[]>(`/assessments/${a.id}/reports`, 3000);
  const download = async (fmt: "json" | "md") => {
    setBusy(true); setErr(undefined);
    try {
      const body = await api<string>(`/assessments/${a.id}/report?format=${fmt}`, { raw: true });
      saveBlob(new Blob([body], { type: fmt === "md" ? "text/markdown" : "application/json" }), `asvas-report-${a.id}.${fmt}`);
    } catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
    finally { setBusy(false); }
  };
  const requestPdf = async () => {
    setErr(undefined);
    try { await api(`/assessments/${a.id}/reports`, { method: "POST" }); docs.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
  };
  const getPdf = async (id: string) => {
    try { saveBlob(await apiBlob(`/reports/${id}/download`), `asvas-report-${id}.pdf`); }
    catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
  };
  return <div className="card">
    <h3>Report</h3>
    <p className="small">Generated from stored state: findings, evidence hashes, CVSS-B scores, retest history, audit-chain check and limitations.
      {a.status !== "COMPLETED" && <b> The assessment is {a.status}; a report now is partial.</b>}</p>
    <div className="actions">
      <button className="btn" disabled={busy} onClick={() => download("json")}>Download JSON</button>
      <button className="btn" disabled={busy} onClick={() => download("md")}>Download Markdown</button>
      <button className="btn" onClick={requestPdf}>Render PDF (report worker)</button>
    </div>
    {err && <div className="state error">{err}</div>}
    <h3 style={{ marginTop: 16 }}>Rendered documents</h3>
    <StateView r={docs} empty={(d) => d.length === 0} emptyText="No PDF rendered yet.">
      {(d) => <div className="tablewrap"><table><thead><tr><th>Requested</th><th>Status</th><th>SHA-256</th><th>Size</th><th /></tr></thead>
        <tbody>{d.map((x) => <tr key={x.id}><td><When t={x.created_at} /></td><td><Badge v={x.status === "READY" ? "SUCCEEDED" : x.status === "FAILED" ? "FAILED" : "QUEUED"} /> {x.status}{x.error && <div className="small bad">{x.error}</div>}</td>
          <td><code className="hash">{x.sha256 ?? "—"}</code></td><td>{x.size_bytes ? `${Math.round(x.size_bytes / 1024)} KB` : "—"}</td>
          <td>{x.status === "READY" && <button className="link" onClick={() => getPdf(x.id)}>Download PDF</button>}</td></tr>)}</tbody></table></div>}
    </StateView>
    {docs.data?.some((x) => x.status === "QUEUED") && <p className="small muted">Queued documents are rendered by the separate <code>asvas report-worker</code> process; if it is not running they stay queued.</p>}
  </div>;
}
