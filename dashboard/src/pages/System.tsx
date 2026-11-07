import { useState } from "react";
import { api, ApiError } from "../api";
import { can, useMe } from "../App";
import { useResource } from "../hooks";
import { Badge, StateView, When } from "../ui";
import { usePersona } from "../persona";

interface Worker { worker_id: string; heartbeat_unix: number; backend: string; isolation_level: string; egress_mode: string; note: string;
  slots: number; running_jobs: number; policy_sha256: string; version: string; uid: number; stale: boolean; loopback_targets_allowed: boolean;
  grpc_addr?: string; syscall_monitor?: string; grpc?: { reachable: boolean; mtls?: boolean; detail?: string } }
interface Status { workers: Worker[]; redis_ok: boolean; policy_engine: { reachable: boolean; policy_loaded: boolean; url: string };
  emergency_stop: boolean; emergency_stop_detail: { reason: string; stopped_at: string } | null;
  planner: { provider: string; is_live_ai: boolean }; unavailable_features: { feature: string; requirement: string; reason: string }[] }

export function SystemPage() {
  const r = useResource<Status>("/system/status", 3000);
  return (
    <section>
      <div className="pagehead"><h1>Workers &amp; policy</h1></div>
      <StateView r={r}>{(s) => <>
        {s.emergency_stop && <div className="banner bad">Emergency stop active since <When t={s.emergency_stop_detail?.stopped_at} />: {s.emergency_stop_detail?.reason}</div>}
        <div className="grid two">
          <div className="card"><h3>Policy engine (control plane)</h3>
            <dl className="kv"><dt>OPA</dt><dd>{s.policy_engine.reachable ? <span className="badge ok">reachable</span> : <span className="badge bad">unreachable</span>} <code>{s.policy_engine.url}</code></dd>
              <dt>Policy loaded</dt><dd>{s.policy_engine.policy_loaded ? "yes" : <span className="bad">no — all actions are denied (fail-closed)</span>}</dd>
              <dt>Event bus</dt><dd>{s.redis_ok ? "Redis reachable" : <span className="bad">Redis unreachable</span>}</dd>
              <dt>Planner</dt><dd>{s.planner.is_live_ai ? `live model provider: ${s.planner.provider}` : "deterministic test planner (not AI)"}</dd></dl>
          </div>
          <div className="card"><h3>Not available in this milestone</h3>
            <ul className="plain">{s.unavailable_features.map((f) => <li key={f.requirement}><span className="unavailable">{f.feature}</span> <span className="small muted">{f.requirement} · {f.reason}</span></li>)}</ul>
          </div>
        </div>
        <h2>Execution workers</h2>
        {s.workers.length === 0 ? <div className="state empty">No executor has registered. Jobs will wait (and time out) until one is running.</div> :
          <div className="grid">{s.workers.map((w) => (
            <div className="card" key={w.worker_id}>
              <div className="cardhead"><b>{w.worker_id}</b> {w.stale ? <span className="badge bad">stale</span> : <span className="badge ok">alive</span>} {w.stale && <span className="small bad">heartbeat stale</span>}</div>
              <dl className="kv">
                <dt>Backend</dt><dd>{w.backend}</dd>
                <dt>Isolation</dt><dd>{w.isolation_level}<div className="small warn">{w.note}</div></dd>
                <dt>Egress control</dt><dd>{w.egress_mode}</dd>
                <dt>Syscall monitor</dt><dd>{w.syscall_monitor ?? <span className="muted">not reported</span>}</dd>
                <dt>Direct channel</dt><dd>{w.grpc?.reachable
                  ? <><span className="badge ok">gRPC · mutual TLS 1.3</span> <code className="small">{w.grpc_addr}</code></>
                  : <span className="muted">unavailable{w.grpc?.detail ? ` — ${w.grpc.detail}` : ""} (control still flows via signed Redis stream)</span>}</dd>
                <dt>Slots</dt><dd>{w.running_jobs} running / {w.slots}</dd>
                <dt>Policy bundle</dt><dd><code className="hash">{w.policy_sha256}</code></dd>
                <dt>Loopback targets</dt><dd>{w.loopback_targets_allowed ? "allowed (dev)" : "refused"}</dd>
                <dt>Heartbeat</dt><dd><When t={new Date(w.heartbeat_unix * 1000).toISOString()} /> · uid {w.uid} · v{w.version}</dd>
              </dl>
            </div>))}</div>}
        <PolicySource />
      </>}</StateView>
    </section>
  );
}

function PolicySource() {
  const me = useMe();
  const { persona } = usePersona();
  const [open, setOpen] = useState(false);
  const r = useResource<{ files: { path: string; sha256: string; source: string }[] }>(open ? "/system/policy" : null);
  if (persona !== "advanced" || !can(me, "operator")) return null;
  return <>
    <h2>Policy source (read-only)</h2>
    <p className="small muted">The Rego policy the control plane loads. Changing policy is a reviewed code change, not a dashboard action.</p>
    <details onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}><summary>Show policy files</summary>
      {open && <StateView r={r}>{(d) => <>{d.files.map((f) => <div key={f.path} className="card">
        <div className="cardhead"><code>{f.path}</code> <code className="hash small">{f.sha256}</code></div>
        <pre className="small">{f.source}</pre></div>)}</>}</StateView>}
    </details>
  </>;
}

export function EmergencyStopButton() {
  const me = useMe();
  const s = useResource<Status>("/system/status", 5000);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string>();
  const active = s.data?.emergency_stop;
  if (!can(me, "admin")) return active ? <Badge v="FAILED" /> : null;
  const call = async (path: string, body?: unknown) => {
    setErr(undefined);
    try { await api(path, { method: "POST", body }); setOpen(false); setReason(""); s.reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
  };
  if (active) return <div className="actions"><span className="badge bad">EMERGENCY STOP ACTIVE</span>
    <button className="btn" onClick={() => call("/system/emergency-stop/reset")}>Reset</button></div>;
  return (
    <div className="actions">
      {!open ? <button className="btn danger" onClick={() => setOpen(true)}>Emergency stop</button> : <>
        <input placeholder="Reason (required)" value={reason} onChange={(e) => setReason(e.target.value)} />
        <button className="btn danger" disabled={reason.trim().length < 3} onClick={() => call("/system/emergency-stop", { reason })}>Stop all tenant activity</button>
        <button className="btn" onClick={() => setOpen(false)}>Cancel</button></>}
      {err && <span className="bad small">{err}</span>}
    </div>
  );
}
