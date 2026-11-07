"""PL-05: durable blocked paths. DA-14: monthly range partitions for the audit event history.

audit_events is rebuilt as a table partitioned by created_at (monthly), preserving every row, id and hash, the
RLS policy, the append-only trigger and grants. Partitions are never dropped (the audit ledger is not transient);
partitioning bounds index size and allows partition-level archiving. A DEFAULT partition catches rows outside
the pre-created months so an audit write can never fail for lack of a partition; the Controls view flags it if
it is ever non-empty. Evidence is NOT partitioned: its sealed content is bound (AES-GCM AAD) to row identity and
its guard trigger permits key re-wrapping updates, and its volume is bounded by per-assessment request budgets.

Revision ID: 0010
"""
from alembic import op

revision = "0010"
down_revision = "0009"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE blocked_paths (
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        consecutive_failures INT NOT NULL,
        job_id UUID,
        blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (assessment_id, path)
    )""")
    for stmt in ("ALTER TABLE blocked_paths ENABLE ROW LEVEL SECURITY", "ALTER TABLE blocked_paths FORCE ROW LEVEL SECURITY",
                 "CREATE POLICY tenant_isolation ON blocked_paths FOR ALL "
                 "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
                 "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)",
                 "GRANT SELECT, INSERT ON blocked_paths TO asvas_app"):
        op.execute(stmt)

    # ---- audit_events -> monthly partitions
    # The migration role owns the table but FORCE ROW LEVEL SECURITY applies to owners too: without a tenant set it
    # would see zero rows and silently copy nothing. Lift FORCE on the old table for the copy and verify counts.
    op.execute("ALTER TABLE audit_events NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_events RENAME TO audit_events_old")
    op.execute("ALTER INDEX ix_audit_tenant RENAME TO ix_audit_tenant_old")
    op.execute("ALTER INDEX ix_audit_assessment RENAME TO ix_audit_assessment_old")
    op.execute("ALTER TABLE audit_events_old RENAME CONSTRAINT audit_events_pkey TO audit_events_old_pkey")
    op.execute("""
    CREATE TABLE audit_events (
        id BIGINT NOT NULL DEFAULT nextval('audit_events_id_seq'),
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        assessment_id UUID,
        actor TEXT NOT NULL,
        event_type TEXT NOT NULL,
        data JSONB NOT NULL DEFAULT '{}',
        prev_hash CHAR(64) NOT NULL,
        hash CHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        PRIMARY KEY (id, created_at)
    ) PARTITION BY RANGE (created_at)""")
    op.execute("CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT")
    op.execute(r"""
    CREATE FUNCTION asvas_ensure_audit_partitions(months_ahead INT DEFAULT 3) RETURNS SETOF TEXT
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    DECLARE m DATE; name TEXT; first DATE;
    BEGIN
      IF months_ahead < 0 OR months_ahead > 24 THEN RAISE EXCEPTION 'months_ahead out of range'; END IF;
      SELECT date_trunc('month', coalesce(min(created_at), now()))::date INTO first FROM audit_events_default;
      first := least(first, date_trunc('month', now())::date);
      FOR m IN SELECT generate_series(first, date_trunc('month', now())::date + make_interval(months => months_ahead),
                                      interval '1 month')::date LOOP
        name := 'audit_events_' || to_char(m, 'YYYYMM');
        IF to_regclass(name) IS NULL THEN
          IF EXISTS (SELECT 1 FROM audit_events_default WHERE created_at >= m AND created_at < (m + interval '1 month')) THEN
            RAISE WARNING 'rows for % are in audit_events_default; partition not created', name;
            CONTINUE;
          END IF;
          EXECUTE format('CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                         name, m::timestamptz, (m + interval '1 month')::timestamptz);
          RETURN NEXT name;
        END IF;
      END LOOP;
    END $$""")
    op.execute("""
    DO $$ DECLARE m DATE; BEGIN
      FOR m IN SELECT generate_series(date_trunc('month', coalesce((SELECT min(created_at) FROM audit_events_old), now())),
                                      date_trunc('month', now()) + interval '3 months', interval '1 month')::date LOOP
        EXECUTE format('CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                       'audit_events_' || to_char(m, 'YYYYMM'), m::timestamptz, (m + interval '1 month')::timestamptz);
      END LOOP;
    END $$""")
    op.execute("INSERT INTO audit_events (id, tenant_id, assessment_id, actor, event_type, data, prev_hash, hash, created_at) "
               "SELECT id, tenant_id, assessment_id, actor, event_type, data, prev_hash, hash, created_at "
               "FROM audit_events_old ORDER BY id")
    op.execute("""
    DO $$ BEGIN
      IF (SELECT count(*) FROM audit_events) <> (SELECT count(*) FROM audit_events_old) THEN
        RAISE EXCEPTION 'audit_events copy incomplete';
      END IF;
    END $$""")
    op.execute("ALTER SEQUENCE audit_events_id_seq OWNED BY audit_events.id")
    op.execute("DROP TABLE audit_events_old")
    op.execute("CREATE INDEX ix_audit_tenant ON audit_events(tenant_id, id DESC)")
    op.execute("CREATE INDEX ix_audit_assessment ON audit_events(assessment_id, id)")
    op.execute("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_events FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON audit_events FOR ALL "
               "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
               "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)")
    op.execute("CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events "
               "FOR EACH ROW EXECUTE FUNCTION asvas_block_mutation()")
    op.execute("GRANT SELECT, INSERT ON audit_events TO asvas_app")
    op.execute("REVOKE ALL ON FUNCTION asvas_ensure_audit_partitions(INT) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION asvas_ensure_audit_partitions(INT) TO asvas_app")


def downgrade() -> None:
    raise NotImplementedError
