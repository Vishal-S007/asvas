// UI-04: read-only control status for external auditors. No action buttons by design.
import { useResource } from "../hooks";
import { StateView, When } from "../ui";

interface Control { id: string; requirement: string; title: string; status: "pass" | "attention" | "info"; detail: string; data: Record<string, unknown> }

const TONE = { pass: "ok", attention: "warn", info: "muted" } as const;

export function ControlsPage() {
  const r = useResource<{ generated_at: number; tenant_id: string; controls: Control[] }>("/compliance/controls", 30000);
  return (
    <section>
      <div className="pagehead"><h1>Controls (read-only)</h1></div>
      <p className="small muted">Computed live from this deployment each time the page loads. This is a status view for review, not a
        compliance certification; mapping to NIST / ISO / SOC 2 is not implemented (DA-12).</p>
      <StateView r={r}>{(d) => <>
        <div className="small muted">Generated <When t={new Date(d.generated_at * 1000).toISOString()} /> · tenant <code>{d.tenant_id}</code></div>
        <div className="tablewrap"><table>
          <thead><tr><th>Status</th><th>Control</th><th>Req.</th><th>Detail</th><th>Data</th></tr></thead>
          <tbody>{d.controls.map((c) => <tr key={c.id}>
            <td><span className={`badge ${TONE[c.status]}`}>{c.status}</span></td>
            <td><b>{c.title}</b></td><td className="small">{c.requirement}</td><td>{c.detail}</td>
            <td>{Object.keys(c.data).length ? <details><summary className="small">view</summary><pre>{JSON.stringify(c.data, null, 2)}</pre></details> : "—"}</td>
          </tr>)}</tbody>
        </table></div>
      </>}</StateView>
    </section>
  );
}
