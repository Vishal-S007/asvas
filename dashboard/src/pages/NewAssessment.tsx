import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { api, ApiError, type Assessment } from "../api";
import { can, useMe } from "../App";

const TOOLS = [
  { id: "http.security_headers", label: "HTTP security headers & cookies (low risk)" },
  { id: "http.allowed_methods", label: "Advertised HTTP methods via OPTIONS (medium risk)" },
];

function localInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

interface TargetRow { host: string; ports: string; http: boolean; https: boolean }

export function NewAssessmentPage() {
  const me = useMe();
  const nav = useNavigate();
  const now = useMemo(() => new Date(), []);
  const [name, setName] = useState("Local test target");
  const [description, setDescription] = useState("");
  const [targets, setTargets] = useState<TargetRow[]>([{ host: "127.0.0.1", ports: "18080, 18081", http: true, https: false }]);
  const [cidrs, setCidrs] = useState("127.0.0.1/32");
  const [excluded, setExcluded] = useState("");
  const [statement, setStatement] = useState("");
  const [reference, setReference] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [from, setFrom] = useState(localInput(new Date(now.getTime() - 5 * 60000)));
  const [until, setUntil] = useState(localInput(new Date(now.getTime() + 24 * 3600000)));
  const [tools, setTools] = useState<string[]>(["http.security_headers", "http.allowed_methods"]);
  const [mediumApproval, setMediumApproval] = useState(true);
  const [timeout, setTimeoutS] = useState(20);
  const [rps, setRps] = useState(2);
  const [maxReq, setMaxReq] = useState(100);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  if (!can(me, "operator")) return <div className="state denied">Permission denied: creating assessments requires the operator role.</div>;

  const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErrors([]);
    try {
      const body = {
        name, description,
        scope: {
          targets: targets.map((t) => ({ host: t.host.trim(), ports: list(t.ports).map(Number),
            schemes: [t.http && "http", t.https && "https"].filter(Boolean) })),
          allowed_cidrs: list(cidrs), excluded_cidrs: list(excluded),
          authorization: { statement, reference, authorized_by: authorizedBy,
            valid_from: new Date(from).toISOString(), valid_until: new Date(until).toISOString() },
        },
        testing_policy: { allowed_tools: tools, approval_required_risk_tiers: mediumApproval ? ["medium", "high"] : ["high"],
          job_timeout_seconds: timeout, max_requests_per_second: rps, max_total_requests: maxReq },
      };
      const a = await api<Assessment>("/assessments", { method: "POST", body });
      nav(`/assessments/${a.id}`);
    } catch (err) {
      if (err instanceof ApiError && Array.isArray(err.detail)) {
        setErrors((err.detail as { loc: string[]; msg: string }[]).map((d) => `${d.loc.slice(1).join(".")}: ${d.msg}`));
      } else setErrors([err instanceof ApiError ? err.title : String(err)]);
    } finally { setBusy(false); }
  };

  return (
    <section>
      <div className="pagehead"><h1>New assessment</h1></div>
      <form className="form" onSubmit={submit}>
        <fieldset><legend>General</legend>
          <label>Name<input value={name} onChange={(e) => setName(e.target.value)} required minLength={3} /></label>
          <label>Description<textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} /></label>
        </fieldset>
        <fieldset><legend>Scope (immutable once started)</legend>
          {targets.map((t, i) => (
            <div className="row" key={i}>
              <label>Host (IP or DNS name)<input value={t.host} onChange={(e) => setTargets(targets.map((x, j) => j === i ? { ...x, host: e.target.value } : x))} required /></label>
              <label>Ports<input value={t.ports} onChange={(e) => setTargets(targets.map((x, j) => j === i ? { ...x, ports: e.target.value } : x))} required /></label>
              <label className="check"><input type="checkbox" checked={t.http} onChange={(e) => setTargets(targets.map((x, j) => j === i ? { ...x, http: e.target.checked } : x))} />http</label>
              <label className="check"><input type="checkbox" checked={t.https} onChange={(e) => setTargets(targets.map((x, j) => j === i ? { ...x, https: e.target.checked } : x))} />https</label>
              {targets.length > 1 && <button type="button" className="link" onClick={() => setTargets(targets.filter((_, j) => j !== i))}>Remove</button>}
            </div>
          ))}
          <button type="button" className="btn" onClick={() => setTargets([...targets, { host: "", ports: "443", http: false, https: true }])}>Add target</button>
          <label>Allowed CIDRs — every resolved address must fall inside<input value={cidrs} onChange={(e) => setCidrs(e.target.value)} required /></label>
          <label>Excluded CIDRs<input value={excluded} onChange={(e) => setExcluded(e.target.value)} /></label>
        </fieldset>
        <fieldset><legend>Authorization (required)</legend>
          <label>Authorization statement<textarea value={statement} onChange={(e) => setStatement(e.target.value)} rows={2} required minLength={20}
            placeholder="Who owns the systems and what testing they authorized" /></label>
          <div className="row">
            <label>Reference (ticket / engagement letter)<input value={reference} onChange={(e) => setReference(e.target.value)} required minLength={3} /></label>
            <label>Authorized by<input value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} required minLength={3} /></label>
          </div>
          <div className="row">
            <label>Valid from<input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} required /></label>
            <label>Valid until<input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} required /></label>
          </div>
        </fieldset>
        <fieldset><legend>Testing policy</legend>
          {TOOLS.map((t) => (
            <label className="check" key={t.id}><input type="checkbox" checked={tools.includes(t.id)}
              onChange={(e) => setTools(e.target.checked ? [...tools, t.id] : tools.filter((x) => x !== t.id))} />{t.label}</label>
          ))}
          <label className="check"><input type="checkbox" checked={mediumApproval} onChange={(e) => setMediumApproval(e.target.checked)} />
            Require human approval for medium-risk actions (high-risk always requires approval)</label>
          <div className="row">
            <label>Job timeout (s, ≤30)<input type="number" min={5} max={30} value={timeout} onChange={(e) => setTimeoutS(+e.target.value)} /></label>
            <label>Requests/second (≤10)<input type="number" min={1} max={10} value={rps} onChange={(e) => setRps(+e.target.value)} /></label>
            <label>Total request budget (≤500)<input type="number" min={1} max={500} value={maxReq} onChange={(e) => setMaxReq(+e.target.value)} /></label>
          </div>
          <p className="small muted">Destructive testing, exploit generation and production changes are not available in this platform.</p>
        </fieldset>
        {errors.length > 0 && <div className="state error" role="alert"><b>Rejected by the server:</b><ul>{errors.map((e) => <li key={e}>{e}</li>)}</ul></div>}
        <div className="actions"><button className="btn primary" disabled={busy || tools.length === 0}>{busy ? "Creating…" : "Create draft"}</button></div>
      </form>
    </section>
  );
}
