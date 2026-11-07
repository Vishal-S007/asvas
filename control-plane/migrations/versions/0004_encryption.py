"""Envelope encryption at rest for evidence and rendered reports (CP-11).

Evidence stays append-only: the only permitted UPDATE re-wraps the data key (key rotation); the sealed
content and every other column remain immutable.

Revision ID: 0004
"""
from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    for t in ("evidence", "reports"):
        op.execute(f"ALTER TABLE {t} ADD COLUMN enc_alg TEXT, ADD COLUMN kek_id TEXT, ADD COLUMN dek_wrapped BYTEA")
    op.execute("DROP TRIGGER evidence_append_only ON evidence")
    op.execute("""
    CREATE FUNCTION asvas_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'evidence is append-only' USING ERRCODE = 'insufficient_privilege';
      END IF;
      IF (to_jsonb(NEW) - 'kek_id' - 'dek_wrapped') IS DISTINCT FROM (to_jsonb(OLD) - 'kek_id' - 'dek_wrapped')
         OR OLD.enc_alg IS NULL THEN
        RAISE EXCEPTION 'evidence is append-only (only data-key re-wrapping is permitted)'
          USING ERRCODE = 'insufficient_privilege';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute("CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence "
               "FOR EACH ROW EXECUTE FUNCTION asvas_evidence_guard()")
    op.execute("GRANT UPDATE (kek_id, dek_wrapped) ON evidence TO asvas_app")


def downgrade() -> None:
    raise NotImplementedError
