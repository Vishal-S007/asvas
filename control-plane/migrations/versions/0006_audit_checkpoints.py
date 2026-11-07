"""Signed checkpoints for the write-once audit export (DA-10).

Revision ID: 0006
"""
from alembic import op

revision = "0006"
down_revision = "0005"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE audit_checkpoints (
        id BIGSERIAL PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        seq INTEGER NOT NULL,
        from_id BIGINT NOT NULL,
        to_id BIGINT NOT NULL,
        event_count INTEGER NOT NULL,
        last_hash CHAR(64) NOT NULL,
        segment_name TEXT NOT NULL,
        segment_sha256 CHAR(64) NOT NULL,
        checkpoint_sha256 CHAR(64) NOT NULL,
        signature BYTEA NOT NULL,
        key_fingerprint CHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, seq)
    )""")
    op.execute("ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_checkpoints FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON audit_checkpoints FOR ALL "
               "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
               "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)")
    op.execute("CREATE TRIGGER audit_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_checkpoints "
               "FOR EACH ROW EXECUTE FUNCTION asvas_block_mutation()")
    op.execute("GRANT SELECT, INSERT ON audit_checkpoints TO asvas_app")
    op.execute("GRANT USAGE ON SEQUENCE audit_checkpoints_id_seq TO asvas_app")


def downgrade() -> None:
    raise NotImplementedError
