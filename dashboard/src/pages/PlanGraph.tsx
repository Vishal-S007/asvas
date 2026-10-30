import type { PlanNode } from "../api";

const COLORS: Record<string, string> = { accepted: "var(--info)", job: "var(--info)", rejected: "var(--bad)", denied: "var(--bad)" };
const JOB_COLORS: Record<string, string> = { SUCCEEDED: "var(--ok)", FAILED: "var(--bad)", TIMED_OUT: "var(--bad)", DENIED: "var(--bad)",
  AWAITING_APPROVAL: "var(--warn)", CANCELLED: "var(--muted)" };

/** Layered drawing of the stored planning graph: objective → planning rounds → proposed steps. */
export function PlanGraph({ nodes }: { nodes: PlanNode[] }) {
  const byKey = new Map(nodes.map((n) => [n.node_key, n]));
  const depth = (n: PlanNode): number => (n.parent_key && byKey.has(n.parent_key) ? 1 + depth(byKey.get(n.parent_key)!) : 0);
  const cols: PlanNode[][] = [];
  nodes.forEach((n) => { const d = depth(n); (cols[d] ??= []).push(n); });
  const W = 290, H = 54, GX = 60, GY = 14;
  const pos = new Map<string, { x: number; y: number }>();
  cols.forEach((col, ci) => col.forEach((n, ri) => pos.set(n.node_key, { x: ci * (W + GX), y: ri * (H + GY) })));
  const width = cols.length * (W + GX), height = Math.max(...cols.map((c) => c.length)) * (H + GY);
  return (
    <div className="graphwrap">
      <svg width={width} height={height} role="img" aria-label="Planning graph">
        {nodes.filter((n) => n.parent_key && pos.has(n.parent_key)).map((n) => {
          const a = pos.get(n.parent_key!)!, b = pos.get(n.node_key)!;
          return <path key={`e-${n.node_key}`} d={`M${a.x + W},${a.y + H / 2} C${a.x + W + GX / 2},${a.y + H / 2} ${b.x - GX / 2},${b.y + H / 2} ${b.x},${b.y + H / 2}`}
            fill="none" stroke="var(--border-strong)" />;
        })}
        {nodes.map((n) => {
          const p = pos.get(n.node_key)!;
          const color = n.job_status ? JOB_COLORS[n.job_status] ?? "var(--info)" : COLORS[n.status] ?? "var(--muted)";
          return (
            <g key={n.node_key} transform={`translate(${p.x},${p.y})`}>
              <title>{[n.label, n.job_status ?? n.status, ...n.reasons].join("\n")}</title>
              <rect width={W} height={H} rx={8} fill="var(--panel)" stroke={color} strokeWidth={2} />
              <text x={10} y={21} className="gl">{n.label.length > 40 ? n.label.slice(0, 39) + "…" : n.label}</text>
              <text x={10} y={40} className="gs" fill={color}>{(n.job_status ?? n.status).replace(/_/g, " ")}{n.reasons.length ? ` — ${n.reasons[0].slice(0, 30)}` : ""}</text>
            </g>
          );
        })}
      </svg>
      <p className="small muted">Hover a node for full rejection/denial reasons. Rejected nodes were proposed but blocked by deterministic validation or policy.</p>
    </div>
  );
}
