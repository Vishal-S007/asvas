"""Initial schema: tenants, users, assessments, plan, jobs, approvals, evidence, findings, assets, audit.

Revision ID: 0001
"""
from alembic import op

revision = "0001"
down_revision = None

TENANT_TABLES = [
    "users", "assessments", "plan_nodes", "jobs", "job_results", "approvals", "evidence",
    "assets", "asset_relations", "findings", "finding_retests", "audit_events", "tenant_controls",
]

SCHEMA = r"""
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tenant_controls (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    emergency_stop BOOLEAN NOT NULL DEFAULT false,
    stopped_by UUID,
    stopped_at TIMESTAMPTZ,
    reason TEXT
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer','operator','approver','admin')),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('DRAFT','PLANNING','RUNNING','AWAITING_APPROVAL','REPORTING',
                                           'COMPLETED','FAILED','CANCELLING','CANCELLED')),
    scope JSONB NOT NULL,
    testing_policy JSONB NOT NULL,
    frozen_scope_doc TEXT,            -- canonical JSON frozen at start (signed into every job envelope)
    provider_name TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    planning_rounds INT NOT NULL DEFAULT 0,
    planner_done BOOLEAN NOT NULL DEFAULT false,
    provider_is_live_ai BOOLEAN,
    tokens_used INT NOT NULL DEFAULT 0,
    requests_used INT NOT NULL DEFAULT 0,
    failure_reason TEXT,
    version INT NOT NULL DEFAULT 1
);
CREATE INDEX ix_assessments_tenant ON assessments(tenant_id, created_at DESC);

CREATE TABLE plan_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    node_key TEXT NOT NULL,
    parent_key TEXT,
    round INT NOT NULL,
    kind TEXT NOT NULL,              -- objective | step
    label TEXT NOT NULL,
    status TEXT NOT NULL,            -- proposed | accepted | rejected | denied | job
    reasons JSONB NOT NULL DEFAULT '[]',
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (assessment_id, node_key)
);

CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    plan_node_key TEXT,
    tool_id TEXT NOT NULL,
    risk_tier TEXT NOT NULL CHECK (risk_tier IN ('low','medium','high')),
    category TEXT NOT NULL,
    target JSONB NOT NULL,
    params JSONB NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PROPOSED','DENIED','AWAITING_APPROVAL','QUEUED','RUNNING',
                                           'SUCCEEDED','FAILED','TIMED_OUT','CANCELLED')),
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 2,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    approval_id UUID,
    policy_decision JSONB,
    timeout_seconds INT NOT NULL,
    deadline_at TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT,
    retest_of_finding UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (assessment_id, fingerprint)
);
CREATE INDEX ix_jobs_status ON jobs(tenant_id, status);

CREATE TABLE job_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    attempt INT NOT NULL,
    status TEXT NOT NULL,
    worker_id TEXT,
    backend TEXT,
    egress_mode TEXT,
    error TEXT,
    requests_used INT NOT NULL DEFAULT 0,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (job_id, attempt)
);

CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    binding_hash CHAR(64) NOT NULL,
    binding_summary JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED','INVALIDATED','CONSUMED')),
    requested_by UUID REFERENCES users(id),
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_approvals_pending ON approvals(tenant_id, status);

CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    attempt INT NOT NULL,
    seq INT NOT NULL,
    kind TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content BYTEA NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size_bytes INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (job_id, attempt, seq)
);

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('host','service','endpoint')),
    identifier TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (assessment_id, kind, identifier)
);

CREATE TABLE asset_relations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    src_asset UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dst_asset UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    UNIQUE (src_asset, dst_asset, relation)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id),
    job_id UUID NOT NULL REFERENCES jobs(id),
    check_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    observed_behavior TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    severity_rationale TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    verification_status TEXT NOT NULL CHECK (verification_status IN ('suspected','confirmed')),
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','resolved')),
    cwe TEXT,
    remediation TEXT NOT NULL,
    evidence_ids UUID[] NOT NULL CHECK (cardinality(evidence_ids) > 0),
    fingerprint TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (assessment_id, fingerprint)
);

CREATE TABLE finding_retests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES jobs(id),
    requested_by UUID REFERENCES users(id),
    outcome TEXT NOT NULL CHECK (outcome IN ('pending','still_present','resolved','inconclusive')),
    evidence_ids UUID[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assessment_id UUID,
    actor TEXT NOT NULL,              -- user:<uuid> | system:<component>
    event_type TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    prev_hash CHAR(64) NOT NULL,
    hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ix_audit_tenant ON audit_events(tenant_id, id DESC);
CREATE INDEX ix_audit_assessment ON audit_events(assessment_id, id);

-- Append-only enforcement for ledger-like tables.
CREATE FUNCTION asvas_block_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION asvas_block_mutation();
CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence
  FOR EACH ROW EXECUTE FUNCTION asvas_block_mutation();

-- Narrow, audited cross-tenant lookup used only by authentication (returns one user's identity row).
CREATE FUNCTION asvas_lookup_user(p_user_id UUID, p_email TEXT)
RETURNS TABLE (id UUID, tenant_id UUID, email TEXT, display_name TEXT, role TEXT, active BOOLEAN)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.id, u.tenant_id, u.email, u.display_name, u.role, u.active FROM users u
  WHERE (p_user_id IS NOT NULL AND u.id = p_user_id) OR (p_email IS NOT NULL AND u.email = p_email)
  LIMIT 1
$$;
"""


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} FOR ALL "
            f"USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
            f"WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)"
        )
    op.execute("GRANT SELECT ON tenants TO asvas_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON " + ", ".join(t for t in TENANT_TABLES
               if t not in ("audit_events", "evidence")) + " TO asvas_app")
    op.execute("GRANT SELECT, INSERT ON audit_events, evidence TO asvas_app")
    op.execute("GRANT USAGE ON SEQUENCE audit_events_id_seq TO asvas_app")
    op.execute("GRANT USAGE, CREATE ON SCHEMA public TO asvas_auth_definer")
    op.execute("GRANT SELECT ON users TO asvas_auth_definer")
    op.execute("ALTER FUNCTION asvas_lookup_user(UUID, TEXT) OWNER TO asvas_auth_definer")
    op.execute("REVOKE ALL ON FUNCTION asvas_lookup_user(UUID, TEXT) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION asvas_lookup_user(UUID, TEXT) TO asvas_app")
    op.execute("REVOKE CREATE ON SCHEMA public FROM asvas_auth_definer")


def downgrade() -> None:
    raise NotImplementedError("Downgrade of the initial schema is intentionally unsupported (audit data).")
