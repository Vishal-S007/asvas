"""Entry points: `asvas migrate | seed-dev | api | orchestrator | verify-audit`."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time

from asvas.config import get_settings

log = logging.getLogger("asvas")


def _pg_url(sqlalchemy_url: str) -> str:
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://")


def migrate(url: str | None = None) -> None:
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from langgraph.checkpoint.postgres import PostgresSaver

    s = get_settings()
    owner = url or s.migration_database_url
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "migrations"))
    cfg.attributes["url"] = owner
    command.upgrade(cfg, "head")
    with PostgresSaver.from_conn_string(_pg_url(owner)) as saver:
        saver.setup()
    import psycopg
    with psycopg.connect(_pg_url(owner), autocommit=True) as c:
        c.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoints, checkpoint_blobs, checkpoint_writes, "
                  "checkpoint_migrations TO asvas_app")
    print("migrations applied")


def make_checkpointer():
    from langgraph.checkpoint.postgres import PostgresSaver
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(_pg_url(get_settings().database_url), max_size=4, open=True,
                          kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row})
    return PostgresSaver(pool)


def run_orchestrator(stop_after: float | None = None) -> None:
    from asvas.orchestration import bus, engine

    deps = engine.Deps(checkpointer=make_checkpointer())
    r = deps.r
    bus.ensure_groups(r)
    consumer = f"orch-{int(time.time())}"
    running = True

    def _stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    last_reap = 0.0
    started = time.time()
    log.info("orchestrator %s started (planner=%s)", consumer, get_settings().model_provider)
    while running and (stop_after is None or time.time() - started < stop_after):
        # Recover messages left unacknowledged by a crashed orchestrator (handlers are idempotent).
        for stream in (bus.RESULTS, bus.ORCH):
            r.xautoclaim(stream, bus.ORCH_GROUP, consumer, min_idle_time=60000, start_id="0-0", count=20)
        resp = r.xreadgroup(bus.ORCH_GROUP, consumer, {bus.RESULTS: ">", bus.ORCH: ">"}, count=20, block=1000) or []
        pending = [(s, mid, f) for s, msgs in resp for mid, f in msgs]
        for stream, mid, fields in pending:
            try:
                handle(deps, stream, fields)
            except Exception:  # noqa: BLE001
                log.exception("handler failed for %s %s", stream, mid)
            r.xack(stream, bus.ORCH_GROUP, mid)
        if time.time() - last_reap > 5:
            try:
                n = engine.reap(deps)
                if n:
                    log.warning("reaper timed out %d job(s)", n)
            except Exception:  # noqa: BLE001
                log.exception("reaper failed")
            last_reap = time.time()


def handle(deps, stream: str, fields: dict) -> None:
    from asvas.orchestration import bus, engine

    if stream == bus.RESULTS:
        engine.ingest_result(deps, fields["result"], fields["sig"])
    elif stream == bus.ORCH:
        msg = json.loads(fields["message"])
        if msg["type"] == "plan":
            engine.run_planning_round(deps, msg["tenant_id"], msg["assessment_id"])


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser("asvas")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    sub.add_parser("seed-dev")
    api = sub.add_parser("api")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    sub.add_parser("orchestrator")
    sub.add_parser("verify-audit")
    sub.add_parser("graph-resync", help="rebuild the Neo4j projection from PostgreSQL")
    a = p.parse_args(argv)
    if a.cmd == "migrate":
        migrate()
    elif a.cmd == "seed-dev":
        s = get_settings()
        if s.env == "production":
            print("refusing to seed development users in production", file=sys.stderr)
            return 2
        from sqlalchemy import create_engine

        from asvas.seed import seed
        seed(create_engine(s.migration_database_url))
        print("development users seeded")
    elif a.cmd == "api":
        import uvicorn

        from asvas.api.app import create_app
        uvicorn.run(create_app(), host=a.host, port=a.port, log_level="info")
    elif a.cmd == "orchestrator":
        run_orchestrator()
    elif a.cmd == "graph-resync":
        from asvas.db import list_tenant_ids, rows, tenant_tx
        from asvas.orchestration.engine import Deps, sync_graph
        deps = Deps()
        if deps.graph_store.name == "disabled":
            print("graph store disabled (ASVAS_NEO4J_URI unset)", file=sys.stderr)
            return 2
        failures = 0
        for t in list_tenant_ids():
            with tenant_tx(t) as conn:
                ids = [r["id"] for r in rows(conn, "SELECT id FROM assessments WHERE started_at IS NOT NULL")]
            for aid in ids:
                failures += bool(sync_graph(deps, t, aid))
        print(f"resynced; failures={failures}")
        return 1 if failures else 0
    elif a.cmd == "verify-audit":
        from asvas.audit import verify_chain
        from asvas.db import list_tenant_ids, tenant_tx
        ok = True
        for t in list_tenant_ids():
            with tenant_tx(t) as conn:
                res = verify_chain(conn, t)
            print(t, res)
            ok &= res["ok"]
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
