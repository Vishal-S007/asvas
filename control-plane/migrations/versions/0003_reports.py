"""Rendered report documents produced by the separate report-rendering worker (DA-11).

Revision ID: 0003
"""
from alembic import op

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE reports (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        requested_by UUID REFERENCES users(id),
        format TEXT NOT NULL CHECK (format IN ('pdf')),
        status TEXT NOT NULL CHECK (status IN ('QUEUED','RENDERING','READY','FAILED')),
        content BYTEA,
        sha256 CHAR(64),
        size_bytes INT,
        error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        completed_at TIMESTAMPTZ
    )""")
    op.execute("CREATE INDEX ix_reports_assessment ON reports(assessment_id, created_at DESC)")
    op.execute("ALTER TABLE reports ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE reports FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON reports FOR ALL "
               "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
               "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)")
    op.execute("GRANT SELECT, INSERT, UPDATE ON reports TO asvas_app")


def downgrade() -> None:
    op.execute("DROP TABLE reports")
