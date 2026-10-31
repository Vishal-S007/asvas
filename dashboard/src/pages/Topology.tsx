import { useResource } from "../hooks";
import { StateView } from "../ui";

interface GNode { id: string; type: "Asset" | "Finding"; kind?: string; identifier?: string; title?: string; severity?: string; verification_status?: string; state?: string }
interface Graph { source: string; nodes: GNode[]; edges: { from: string; to: string; type: string; relation?: string }[] }

const SEV: Record<string, string> = { critical: "var(--bad)", high: "var(--bad)", medium: "var(--warn)", low: "var(--info)", info: "var(--muted)" };

/** Topology read from the graph store (Neo4j projection of PostgreSQL state). */
export function Topology({ id }: { id: string }) {
  const r = useResource<Graph>(`/assessments/${id}/graph`);
  if (r.error?.status === 503) return <div className="state">Graph store unavailable: {r.error.title}. Asset data below is read from PostgreSQL.</div>;
  return (
    <StateView r={r} empty={(g) => g.nodes.length === 0} emptyText="The graph store has no nodes for this assessment yet.">
      {(g) => {
        const cols = [
          g.nodes.filter((n) => n.kind === "host"),
          g.nodes.filter((n) => n.kind === "service" || n.kind === "endpoint"),
          g.nodes.filter((n) => n.type === "Finding"),
        ];
        const W = 300, H = 40, GX = 70, GY = 10;
        const pos = new Map<string, { x: number; y: number }>();
        cols.forEach((c, ci) => c.forEach((n, ri) => pos.set(n.id, { x: ci * (W + GX), y: ri * (H + GY) })));
        const height = Math.max(1, ...cols.map((c) => c.length)) * (H + GY);
        return (
          <div className="graphwrap">
            <div className="small muted">Source: <b>{g.source}</b> · {g.nodes.length} nodes · {g.edges.length} edges · host → service → finding</div>
            <svg width={3 * (W + GX)} height={height + 10} role="img" aria-label="Asset topology">
              {g.edges.filter((e) => pos.has(e.from) && pos.has(e.to)).map((e, i) => {
                const a = pos.get(e.from)!, b = pos.get(e.to)!;
                return <path key={i} d={`M${a.x + W},${a.y + H / 2} C${a.x + W + GX / 2},${a.y + H / 2} ${b.x - GX / 2},${b.y + H / 2} ${b.x},${b.y + H / 2}`} fill="none" stroke="var(--border-strong)" />;
              })}
              {g.nodes.filter((n) => pos.has(n.id)).map((n) => {
                const p = pos.get(n.id)!;
                const color = n.type === "Finding" ? SEV[n.severity ?? "info"] : "var(--accent)";
                const label = n.type === "Finding" ? `${n.title}` : `${n.kind}: ${n.identifier}`;
                return <g key={n.id} transform={`translate(${p.x},${p.y})`}>
                  <title>{label}{n.verification_status ? `\n${n.verification_status} · ${n.state}` : ""}</title>
                  <rect width={W} height={H} rx={6} fill="var(--panel)" stroke={color} strokeWidth={1.5} />
                  <text x={8} y={25} className="gl">{label.length > 44 ? label.slice(0, 43) + "…" : label}</text>
                </g>;
              })}
            </svg>
          </div>
        );
      }}
    </StateView>
  );
}
