"""Per-approver Ed25519 signatures on approval decisions (PO-04).

Each approver registers a public key (the private key never leaves the approver's browser / device). A decision
is accepted only with a valid signature over the canonical decision message, made with an active key that belongs
to the deciding user. The signature, key id and message are stored with the approval and in the audit ledger.

Revision ID: 0005
"""
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE approver_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        alg TEXT NOT NULL CHECK (alg = 'Ed25519'),
        public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
        fingerprint CHAR(64) NOT NULL,
        label TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_at TIMESTAMPTZ,
        UNIQUE (tenant_id, fingerprint)
    )""")
    op.execute("CREATE INDEX ix_approver_keys_user ON approver_keys(tenant_id, user_id) WHERE revoked_at IS NULL")
    op.execute("ALTER TABLE approver_keys ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE approver_keys FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON approver_keys FOR ALL "
               "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
               "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)")
    # Keys are never deleted or altered by the application, only revoked.
    op.execute("GRANT SELECT, INSERT ON approver_keys TO asvas_app")
    op.execute("GRANT UPDATE (revoked_at) ON approver_keys TO asvas_app")
    op.execute("ALTER TABLE approvals ADD COLUMN signer_key_id UUID REFERENCES approver_keys(id), "
               "ADD COLUMN signature BYTEA, ADD COLUMN signed_message TEXT")


def downgrade() -> None:
    raise NotImplementedError
