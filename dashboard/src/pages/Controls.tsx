// UI-04 / DA-12: read-only control status for external auditors, with reference framework mappings.
// No action buttons by design (the CSV export is a download, recorded in the audit ledger).
import { useState } from "react";
import { apiBlob, ApiError } from "../api";
import { useResource } from "../hooks";
import { StateView, When } from "../ui";

interface Control { id: string; requirement: string; title: string; status: "pass" | "attention" | "info"; detail: string;
  data: Record<string, unknown>; mappings: Record<string, string[]> }
interface Rule { rule_id: string; cwe: string | null; cwe_name: string | null; owasp_top10_2021: string | null;
  cvss_vector: string | null; cvss_base_score: number | null; unscored_reason: string | null }

const TONE = { pass: "ok", attention: "warn", info: "muted" } as const;

export function ControlsPage() {
  const r = useResource<{ generated_at: number; tenant_id: string; frameworks: Record<string, string>; mapping_disclaimer: string;
    controls: Control[] }>("/compliance/controls", 30000);
  const rules = useResource<Rule[]>("/rules");
  const [err, setErr] = useState<string>();
  const download = async () => {
    setErr(undefined);
    try { const b = await apiBlob("/compliance/controls.csv"); const a = document.createElement("a");
      a.href = URL.createObjectURL(b); a.download = "asvas-controls.csv"; a.click(); URL.revokeObjectURL(a.href); }
    catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
  };
  return (
    <section>
      <div className="pagehead"><h1>Controls (read-only)</h1><button className="btn" onClick={download}>Download CSV</button></div>
      <p className="small muted">Computed live from this deployment each time the page loads. Status is a technical check, not a
        compliance certification.</p>
      {err && <div className="state error" role="alert">{err}</div>}
      <StateView r={r}>{(d) => <>
        <div className="banner">{d.mapping_disclaimer}</div>
        <div className="small muted">Generated <When t={new Date(d.generated_at * 1000).toISOString()} /> · tenant <code>{d.tenant_id}</code></div>
        <div className="tablewrap"><table>
          <thead><tr><th>Status</th><th>Control</th><th>Req.</th><th>Detail</th>
            {Object.values(d.frameworks).map((f) => <th key={f} className="small">{f}</th>)}<th>Data</th></tr></thead>
          <tbody>{d.controls.map((c) => <tr key={c.id}>
            <td><span className={`badge ${TONE[c.status]}`}>{c.status}</span></td>
            <td><b>{c.title}</b></td><td className="small">{c.requirement}</td><td>{c.detail}</td>
            {Object.keys(d.frameworks).map((k) => <td key={k} className="small">{(c.mappings[k] ?? []).join(", ") || "—"}</td>)}
            <td>{Object.keys(c.data).length ? <details><summary className="small">view</summary><pre>{JSON.stringify(c.data, null, 2)}</pre></details> : "—"}</td>
          </tr>)}</tbody>
        </table></div>
      </>}</StateView>
      <h2>Finding rules</h2>
      <p className="small muted">Every finding the platform can report, with its weakness (CWE), OWASP Top 10 (2021) category and fixed CVSS 4.0 base vector.</p>
      <StateView r={rules}>{(rs) => <div className="tablewrap"><table>
        <thead><tr><th>Rule</th><th>CWE</th><th>OWASP Top 10</th><th>CVSS 4.0</th></tr></thead>
        <tbody>{rs.map((x) => <tr key={x.rule_id}><td><code>{x.rule_id}</code></td>
          <td className="small">{x.cwe ? `${x.cwe} ${x.cwe_name}` : "—"}</td><td className="small">{x.owasp_top10_2021 ?? "—"}</td>
          <td className="small">{x.cvss_vector ? <><b>{x.cvss_base_score}</b> <code>{x.cvss_vector}</code></> : <span className="muted">{x.unscored_reason}</span>}</td></tr>)}</tbody>
      </table></div>}</StateView>
    </section>
  );
}
