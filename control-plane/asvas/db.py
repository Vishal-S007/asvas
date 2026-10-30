"""Database access. Every tenant-scoped transaction sets app.current_tenant_id so PostgreSQL RLS applies."""

from __future__ import annotations

import functools
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Connection, Engine, create_engine, text

from asvas.config import get_settings


@functools.lru_cache
def get_engine(url: str | None = None) -> Engine:
    return create_engine(url or get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=5)


@contextmanager
def tenant_tx(tenant_id: uuid.UUID | str, engine: Engine | None = None) -> Iterator[Connection]:
    """Open a transaction bound to one tenant. RLS makes rows of other tenants invisible and unwritable."""
    eng = engine or get_engine()
    with eng.begin() as conn:
        conn.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant_id)})
        yield conn


@contextmanager
def system_tx(engine: Engine | None = None) -> Iterator[Connection]:
    """Transaction with no tenant bound: only non-tenant tables (tenants) are visible."""
    eng = engine or get_engine()
    with eng.begin() as conn:
        yield conn


def rows(conn: Connection, sql: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(r._mapping) for r in conn.execute(text(sql), params)]


def row(conn: Connection, sql: str, **params: Any) -> dict[str, Any] | None:
    r = conn.execute(text(sql), params).first()
    return dict(r._mapping) if r else None


def list_tenant_ids(engine: Engine | None = None) -> list[uuid.UUID]:
    with system_tx(engine) as conn:
        return [r["id"] for r in rows(conn, "SELECT id FROM tenants")]
