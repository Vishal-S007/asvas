import type { ReactNode } from "react";
import { ApiError } from "./api";

export function StateView<T>({ r, empty, children, emptyText = "Nothing here yet." }: {
  r: { data: T | undefined; error: ApiError | undefined; loading: boolean; reload: () => void };
  empty?: (d: T) => boolean; emptyText?: string; children: (d: T) => ReactNode;
}) {
  if (r.error && r.data === undefined) {
    if (r.error.status === 403) return <div className="state denied" role="alert"><b>Permission denied.</b> {r.error.title}</div>;
    if (r.error.status === 404) return <div className="state">Not found.</div>;
    return (
      <div className="state error" role="alert">
        <b>Could not load:</b> {r.error.title} {r.error.status ? `(HTTP ${r.error.status})` : ""}
        <button className="link" onClick={r.reload}>Retry</button>
      </div>
    );
  }
  if (r.data === undefined) return <div className="state loading" aria-busy="true"><span className="spinner" /> Loading…</div>;
  if (empty && empty(r.data)) return <div className="state empty">{emptyText}</div>;
  return (
    <>
      {r.error && <div className="banner warn">Showing last known data — refresh failed: {r.error.title}</div>}
      {children(r.data)}
    </>
  );
}

const STATUS_TONE: Record<string, string> = {
  COMPLETED: "ok", SUCCEEDED: "ok", RUNNING: "info", PLANNING: "info", QUEUED: "info", REPORTING: "info",
  AWAITING_APPROVAL: "warn", PENDING: "warn", CANCELLING: "warn", DRAFT: "muted", PROPOSED: "muted",
  FAILED: "bad", DENIED: "bad", TIMED_OUT: "bad", CANCELLED: "muted", REJECTED: "bad", EXPIRED: "muted",
  INVALIDATED: "muted", APPROVED: "ok", CONSUMED: "muted", accepted: "ok", rejected: "bad", denied: "bad", job: "info",
  critical: "bad", high: "bad", medium: "warn", low: "info", info: "muted", confirmed: "bad", suspected: "warn",
  open: "warn", resolved: "ok", still_present: "bad", inconclusive: "muted",
};

export function Badge({ v }: { v: string | null | undefined }) {
  if (!v) return <span className="badge muted">—</span>;
  return <span className={`badge ${STATUS_TONE[v] ?? "muted"}`}>{v.replace(/_/g, " ")}</span>;
}

export function When({ t }: { t: string | null | undefined }) {
  if (!t) return <span className="muted">—</span>;
  const d = new Date(t);
  return <time dateTime={t} title={d.toISOString()}>{d.toLocaleString()}</time>;
}

export function Unavailable({ feature, req }: { feature: string; req: string }) {
  return <span className="unavailable" title={`Not implemented in this milestone (${req})`}>{feature}: unavailable ({req})</span>;
}

export function PlannerLabel({ name, live }: { name: string | null | undefined; live: boolean | null | undefined }) {
  if (!name) return <span className="muted">not planned yet</span>;
  return live
    ? <span className="badge info">Live model: {name}</span>
    : <span className="badge muted" title="Rule-based planner for development and CI. This is not an AI assessment.">
        Deterministic test planner — not AI
      </span>;
}
