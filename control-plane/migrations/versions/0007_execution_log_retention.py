"""Transient execution log, partitioned by day, with a 30-day retention floor (DA-14; spec pp. 77, 84-85).

`execution_log` holds operational detail about job execution (dispatch, per-request summaries, results). It is
transient by design: evidence and the audit ledger are kept separately and are not subject to this retention.

Partition maintenance runs through two SECURITY DEFINER functions owned by the schema owner, so the application
role can create tomorrow's partitions and drop expired ones without holding DDL rights. The drop function refuses
any retention shorter than 30 days, so a compromised application role cannot use it to erase recent logs.

Revision ID: 0007
"""
from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE execution_log (
        id BIGINT GENERATED ALWAYS AS IDENTITY,
        tenant_id UUID NOT NULL,
        assessment_id UUID,
        job_id UUID NOT NULL,
        attempt INT NOT NULL,
        event TEXT NOT NULL,
        detail JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    ) PARTITION BY RANGE (created_at)""")
    op.execute("CREATE INDEX ix_execution_log_job ON execution_log (tenant_id, job_id, id)")
    op.execute("ALTER TABLE execution_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execution_log FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON execution_log FOR ALL "
               "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
               "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)")
    op.execute("GRANT SELECT, INSERT ON execution_log TO asvas_app")

    op.execute(r"""
    CREATE FUNCTION asvas_ensure_log_partitions(days_ahead INT DEFAULT 7) RETURNS SETOF TEXT
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    DECLARE d DATE; name TEXT;
    BEGIN
      IF days_ahead < 0 OR days_ahead > 31 THEN RAISE EXCEPTION 'days_ahead out of range'; END IF;
      FOR d IN SELECT generate_series(current_date - 1, current_date + days_ahead, interval '1 day')::date LOOP
        name := 'execution_log_' || to_char(d, 'YYYYMMDD');
        IF to_regclass(name) IS NULL THEN
          EXECUTE format('CREATE TABLE %I PARTITION OF execution_log FOR VALUES FROM (%L) TO (%L)',
                         name, d::timestamptz, (d + 1)::timestamptz);
          RETURN NEXT name;
        END IF;
      END LOOP;
    END $$""")
    op.execute(r"""
    CREATE FUNCTION asvas_drop_expired_log_partitions(retention_days INT)
    RETURNS TABLE (partition_name TEXT, tenant_id UUID, row_count BIGINT)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    DECLARE p RECORD; upper_bound TIMESTAMPTZ; cutoff TIMESTAMPTZ;
    BEGIN
      IF retention_days < 30 THEN
        RAISE EXCEPTION 'retention below the 30-day minimum is refused' USING ERRCODE = 'insufficient_privilege';
      END IF;
      -- One extra day of margin: a log line is written at most one job timeout (< 1 day) before job completion,
      -- so every dropped row belongs to a job that completed at least retention_days ago.
      cutoff := date_trunc('day', now()) - make_interval(days => retention_days + 1);
      FOR p IN SELECT c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound FROM pg_inherits i
               JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'execution_log'::regclass LOOP
        upper_bound := substring(p.bound FROM 'TO \(''([^'']+)''\)')::timestamptz;
        IF upper_bound <= cutoff THEN
          RETURN QUERY EXECUTE format('SELECT %L::text, tenant_id, count(*) FROM %I GROUP BY tenant_id',
                                      p.relname, p.relname);
          EXECUTE format('DROP TABLE %I', p.relname);
        END IF;
      END LOOP;
    END $$""")
    op.execute("REVOKE ALL ON FUNCTION asvas_ensure_log_partitions(INT) FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION asvas_drop_expired_log_partitions(INT) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION asvas_ensure_log_partitions(INT) TO asvas_app")
    op.execute("GRANT EXECUTE ON FUNCTION asvas_drop_expired_log_partitions(INT) TO asvas_app")
    op.execute("SELECT asvas_ensure_log_partitions(14)")


def downgrade() -> None:
    raise NotImplementedError
