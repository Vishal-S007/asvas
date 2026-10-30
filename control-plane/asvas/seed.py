"""Development seed data. Only used when ASVAS_ENV=development/test."""

from __future__ import annotations

from sqlalchemy import Engine, text

from asvas.db import tenant_tx

# (email, display name, role, tenant)
DEV_USERS = [
    ("admin@acme.test", "Ada Admin", "admin", "acme"),
    ("approver@acme.test", "Arun Approver", "approver", "acme"),
    ("operator@acme.test", "Olu Operator", "operator", "acme"),
    ("viewer@acme.test", "Vic Viewer", "viewer", "acme"),
    ("operator@globex.test", "Gil Globex", "operator", "globex"),
]


def seed(owner_engine: Engine) -> None:
    with owner_engine.begin() as conn:
        for name in sorted({u[3] for u in DEV_USERS}):
            conn.execute(text("INSERT INTO tenants (name) VALUES (:n) ON CONFLICT (name) DO NOTHING"), {"n": name})
        tenants = {r.name: r.id for r in conn.execute(text("SELECT id, name FROM tenants"))}
    for email, display, role, tenant in DEV_USERS:
        with tenant_tx(tenants[tenant], owner_engine) as conn:
            conn.execute(text("INSERT INTO users (tenant_id, email, display_name, role) VALUES (:t,:e,:d,:r) "
                              "ON CONFLICT (email) DO NOTHING"),
                         {"t": str(tenants[tenant]), "e": email, "d": display, "r": role})
