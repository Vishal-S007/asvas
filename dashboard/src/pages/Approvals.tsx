import { useState } from "react";
import { Link } from "react-router";
import { api, ApiError, type Approval } from "../api";
import { can, useMe } from "../App";
import { useResource } from "../hooks";
import { signDecision } from "../signing";
import { Badge, StateView, When } from "../ui";

export function ApprovalCard({ a, onDone }: { a: Approval; onDone: () => void }) {
  const me = useMe();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  const [reason, setReason] = useState("");
  const decide = async (decision: "approve" | "reject") => {
    setBusy(true); setMsg(undefined);
    try {
      const sig = await signDecision(me.user_id, a.id, decision, a.binding_hash, a.expires_unix);
      await api(`/approvals/${a.id}/decision`, { method: "POST", body: { decision, binding_hash: a.binding_hash, reason: reason || null, ...sig } });
      onDone();
    } catch (e) { setMsg(e instanceof ApiError ? `${e.title} (HTTP ${e.status})` : String(e)); }
    finally { setBusy(false); }
  };
  const t = a.binding_summary.target;
  const pending = a.status === "PENDING" && !a.is_expired;
  return (
    <div className="card approval">
      <div className="cardhead"><b>{a.binding_summary.tool_id}</b> <Badge v={a.binding_summary.risk_tier} /> <Badge v={a.is_expired && a.status === "PENDING" ? "EXPIRED" : a.status} /></div>
      <dl className="kv">
        <dt>Assessment</dt><dd><Link to={`/assessments/${a.assessment_id}`}>{a.assessment_name}</Link></dd>
        <dt>Target</dt><dd><code>{t.scheme}://{t.host}:{t.port}</code></dd>
        <dt>Parameters</dt><dd><code>{JSON.stringify(a.binding_summary.params)}</code></dd>
        <dt>Bound to hash</dt><dd><code className="hash">{a.binding_hash}</code></dd>
        <dt>Expires</dt><dd><When t={a.expires_at} /></dd>
        {a.signer_key_id && <><dt>Signed with key</dt><dd><code>{a.signer_key_id}</code> (Ed25519)</dd></>}
      </dl>
      <p className="small muted">Approval applies only to exactly this action and parameters, once, before expiry. The requester cannot approve. Your decision is signed with your own Ed25519 key held in this browser.</p>
      {pending && (can(me, "approver") ? (
        <div className="actions">
          <input placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
          <button className="btn primary" disabled={busy} onClick={() => decide("approve")}>Approve</button>
          <button className="btn danger" disabled={busy} onClick={() => decide("reject")}>Reject</button>
        </div>
      ) : <div className="small muted">Deciding requires the approver role.</div>)}
      {msg && <div className="state error" role="alert">{msg}</div>}
    </div>
  );
}

export function ApprovalsPage() {
  const [filter, setFilter] = useState("PENDING");
  const r = useResource<Approval[]>(`/approvals${filter ? `?status=${filter}` : ""}`, 3000);
  return (
    <section>
      <div className="pagehead"><h1>Approval queue</h1>
        <select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter">
          {["PENDING", "APPROVED", "CONSUMED", "REJECTED", "EXPIRED", "INVALIDATED", ""].map((s) => <option key={s} value={s}>{s || "All"}</option>)}
        </select>
      </div>
      <StateView r={r} empty={(d) => d.length === 0} emptyText="No approvals in this state.">
        {(rows) => <div className="grid">{rows.map((a) => <ApprovalCard key={a.id} a={a} onDone={r.reload} />)}</div>}
      </StateView>
    </section>
  );
}
