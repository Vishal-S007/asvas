// Thin API client. Every response shown in the UI comes from the control plane; nothing is synthesised here.
export class ApiError extends Error {
  constructor(public status: number, public title: string, public detail?: unknown) {
    super(title);
  }
}

const TOKEN_KEY = "asvas.token";
export const tokenStore = {
  get: () => { try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; } },
  set: (t: string) => { try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* ignore */ } },
  clear: () => { try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } },
};

export async function api<T>(path: string, init: { method?: string; body?: unknown; raw?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const t = tokenStore.get();
  if (t) headers.Authorization = `Bearer ${t}`;
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method: init.method ?? "GET", headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  } catch {
    throw new ApiError(0, "Control plane unreachable");
  }
  if (!res.ok) {
    let title = res.statusText, detail: unknown;
    try { const p = await res.json(); title = p.title ?? title; detail = p.detail; } catch { /* non-JSON */ }
    if (res.status === 401) tokenStore.clear();
    throw new ApiError(res.status, title, detail);
  }
  if (init.raw) return (await res.text()) as T;
  return (await res.json()) as T;
}

export type Role = "viewer" | "operator" | "approver" | "admin";
export const rank: Record<Role, number> = { viewer: 0, operator: 1, approver: 2, admin: 3 };

export interface Me { user_id: string; tenant_id: string; email: string; display_name: string; role: Role }
export interface Assessment {
  id: string; name: string; description?: string; status: string; created_at: string; updated_at: string;
  started_at: string | null; finished_at: string | null; provider_name: string | null;
  provider_is_live_ai: boolean | null; failure_reason: string | null; findings?: number; pending_approvals?: number;
  scope?: Scope; testing_policy?: Policy; planning_rounds?: number; tokens_used?: number; requests_used?: number;
  job_counts?: Record<string, number>;
}
export interface Scope {
  targets: { host: string; ports: number[]; schemes: string[] }[];
  allowed_cidrs: string[]; excluded_cidrs: string[];
  authorization: { statement: string; reference: string; authorized_by: string; valid_from: string; valid_until: string };
}
export interface Policy {
  allowed_tools: string[]; approval_required_risk_tiers: string[]; max_requests_per_second: number;
  max_total_requests: number; max_concurrency: number; job_timeout_seconds: number; max_wall_clock_minutes: number;
  max_tokens: number; max_planning_rounds: number; max_plan_depth: number; max_jobs: number; max_attempts: number;
}
export interface Job {
  id: string; tool_id: string; risk_tier: string; target: { scheme: string; host: string; port: number };
  params: Record<string, unknown>; status: string; attempt: number; max_attempts: number; error: string | null;
  requires_approval: boolean; policy_decision: { allow: boolean; deny_reasons: string[]; require_approval: boolean } | null;
  created_at: string; finished_at: string | null; retest_of_finding: string | null;
  last_result: { status: string; backend: string; egress_mode: string; worker_id: string; error: string | null } | null;
}
export interface PlanNode {
  node_key: string; parent_key: string | null; round: number; kind: string; label: string; status: string;
  reasons: string[]; data: Record<string, unknown>; job_status: string | null;
}
export interface Finding {
  id: string; asset: string; check_id: string; rule_id: string; title: string; observed_behavior: string; severity: string;
  severity_rationale: string; confidence: string; verification_status: string; state: string; cwe: string | null;
  remediation: string; evidence_ids: string[]; created_at: string; assessment_id: string;
  retests: { id: string; outcome: string; created_at: string; completed_at: string | null; evidence_ids: string[] }[];
}
export interface Approval {
  id: string; assessment_id: string; assessment_name: string; job_id: string; binding_hash: string; status: string;
  binding_summary: { tool_id: string; risk_tier: string; target: { scheme: string; host: string; port: number }; params: Record<string, unknown> };
  expires_at: string; is_expired: boolean; created_at: string; decided_at: string | null; reason: string | null;
}
export interface AuditEvent { id: number; actor: string; event_type: string; data: Record<string, unknown>; created_at: string; hash: string; assessment_id?: string | null }
