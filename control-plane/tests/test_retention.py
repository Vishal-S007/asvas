"""DA-14: day-partitioned transient execution log, 30-day retention floor, daily maintenance."""

from __future__ import annotations

import datetime as dt
import os
import time

import pytest
from sqlalchemy import create_engine, text

from asvas import retention
from asvas.db import rows, system_tx, tenant_tx
from asvas.orchestration import bus
from tests.test_lifecycle import approval_setup, jobs_of, tid_of


def _owner():
    return create_engine(os.environ["ASVAS_MIGRATION_DATABASE_URL"])


def _make_old_partition(days_ago: int, tenant, job_id) -> str:
    d = dt.date.today() - dt.timedelta(days=days_ago)
    name = f"execution_log_{d:%Y%m%d}"
    eng = _owner()
    with eng.begin() as c:
        c.execute(text(f"DROP TABLE IF EXISTS {name}"))
        c.execute(text(f"CREATE TABLE {name} PARTITION OF execution_log FOR VALUES FROM ('{d}') TO "
                       f"('{d + dt.timedelta(days=1)}')"))
        c.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant)})
        c.execute(text("INSERT INTO execution_log (tenant_id, job_id, attempt, event, created_at) "
                       "VALUES (:t, :j, 1, 'old', :ts)"), {"t": str(tenant), "j": str(job_id),
                                                           "ts": dt.datetime.combine(d, dt.time(12), dt.UTC)})
    eng.dispose()
    return name


def test_dispatch_writes_execution_log(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    apr = client.as_user("approver@acme.test")
    assert client.post(f"/api/v1/approvals/{ap['id']}/decision", json=client.signed(apr, ap), headers=apr).status_code == 200
    jid = jobs_of(aid)[0]["id"]
    log = client.get(f"/api/v1/jobs/{jid}/execution-log", headers=op).json()
    assert [x["event"] for x in log] == ["dispatched"]


def test_retention_drops_only_expired_partitions_and_audits(clean):
    from tests.test_lifecycle import tid_of as t
    tenant = t()
    import uuid
    job = uuid.uuid4()
    old = _make_old_partition(40, tenant, job)
    recent = _make_old_partition(20, tenant, job)
    res = retention.run(None)
    assert old in res["partitions_dropped"] and recent not in res["partitions_dropped"]
    with system_tx() as conn:
        names = {r["relname"] for r in rows(conn, "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON "
                                                  "c.oid = i.inhrelid WHERE i.inhparent = 'execution_log'::regclass")}
    assert old not in names and recent in names
    assert f"execution_log_{dt.date.today() + dt.timedelta(days=7):%Y%m%d}" in names  # partitions created ahead
    with tenant_tx(tenant) as conn:
        ev = rows(conn, "SELECT data FROM audit_events WHERE event_type = 'retention.purged'")
        assert ev and ev[0]["data"]["execution_log_rows"] == 1 and old in ev[0]["data"]["execution_log_partitions"]
        assert rows(conn, "SELECT count(*) AS n FROM execution_log WHERE event = 'old'")[0]["n"] == 1  # 20-day row kept
    _drop(recent)


def _drop(name):
    eng = _owner()
    with eng.begin() as c:
        c.execute(text(f"DROP TABLE IF EXISTS {name}"))
    eng.dispose()


def test_retention_floor_enforced_in_database(clean):
    with pytest.raises(Exception, match="30-day minimum"), system_tx() as conn:
        conn.execute(text("SELECT * FROM asvas_drop_expired_log_partitions(1)"))
    from asvas.config import Settings
    with pytest.raises(ValueError):
        Settings(transient_retention_days=7)


def test_app_role_cannot_read_partitions_directly(clean):
    name = f"execution_log_{dt.date.today():%Y%m%d}"
    with pytest.raises(Exception, match="permission denied"), system_tx() as conn:
        conn.execute(text(f"SELECT * FROM {name}"))


def test_checkpoints_of_old_finished_assessments_purged(client, make_assessment, deps):
    aid, op, job, ap = approval_setup(client, make_assessment, deps)
    eng = _owner()
    with eng.begin() as c:
        c.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tid_of())})
        c.execute(text("INSERT INTO checkpoints (thread_id, checkpoint_ns, checkpoint_id, checkpoint, metadata) "
                       "VALUES (:t, '', 'x', '{}'::jsonb, '{}'::jsonb)"), {"t": f"{aid}:1"})
        c.execute(text("UPDATE assessments SET status = 'COMPLETED', finished_at = now() - interval '31 days' "
                       "WHERE id = :a"), {"a": aid})
    eng.dispose()
    res = retention.run(None)
    assert res["checkpoint_rows_deleted"] >= 1
    with system_tx() as conn:
        assert rows(conn, "SELECT count(*) AS n FROM checkpoints WHERE thread_id LIKE :p", p=f"{aid}:%")[0]["n"] == 0


def test_stream_trim_and_daily_lock(deps):
    r = deps.r
    old_ms = int((time.time() - 40 * 86400) * 1000)
    r.xadd(bus.JOBS, {"x": "old"}, id=f"{old_ms}-0")
    r.xadd(bus.JOBS, {"x": "new"})
    res = retention.maybe_run_daily(r)
    assert res is not None and res["stream_entries_trimmed"][bus.JOBS] >= 1
    assert [f["x"] for _, f in r.xrange(bus.JOBS) if "x" in f] == ["new"]
    assert retention.maybe_run_daily(r) is None  # once per day
