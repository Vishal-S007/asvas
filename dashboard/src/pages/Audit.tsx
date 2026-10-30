import { useState } from "react";
import { Link } from "react-router";
import { api, ApiError, type AuditEvent } from "../api";
import { useResource } from "../hooks";
import { StateView, When } from "../ui";

export function AuditPage() {
  const r = useResource<AuditEvent[]>("/audit?limit=300", 5000);
  const [verify, setVerify] = useState<string>();
  const [q, setQ] = useState("");
  const check = async () => {
    try { const v = await api<{ ok: boolean; events: number; broken_at: number | null }>("/audit/verify");
      setVerify(v.ok ? `Hash chain intact (${v.events} events).` : `CHAIN BROKEN at event ${v.broken_at}`); }
    catch (e) { setVerify(e instanceof ApiError ? e.title : String(e)); }
  };
  return (
    <section>
      <div className="pagehead"><h1>Audit history</h1>
        <div className="actions"><input placeholder="Filter event type / actor" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn" onClick={check}>Verify hash chain</button></div></div>
      {verify && <div className={`banner ${verify.startsWith("Hash") ? "" : "bad"}`}>{verify}</div>}
      <p className="small muted">Append-only, per-tenant SHA-256 hash chain in PostgreSQL. External WORM export is planned (DA-10).</p>
      <StateView r={r} empty={(d) => d.length === 0}>
        {(evs) => <div className="tablewrap"><table>
          <thead><tr><th>#</th><th>Time</th><th>Event</th><th>Actor</th><th>Assessment</th><th>Data</th></tr></thead>
          <tbody>{evs.filter((e) => !q || e.event_type.includes(q) || e.actor.includes(q)).map((e) => <tr key={e.id}>
            <td>{e.id}</td><td><When t={e.created_at} /></td><td><b>{e.event_type}</b></td><td className="small">{e.actor}</td>
            <td className="small">{e.assessment_id ? <Link to={`/assessments/${e.assessment_id}`}>{e.assessment_id.slice(0, 8)}</Link> : "—"}</td>
            <td><details><summary className="small">view</summary><pre>{JSON.stringify(e.data, null, 2)}</pre></details></td>
          </tr>)}</tbody>
        </table></div>}
      </StateView>
    </section>
  );
}
