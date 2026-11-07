"""Read-only auditor role (UI-04; spec p. 60: read-only compliance dashboards for external auditors).

Revision ID: 0009
"""
from alembic import op

revision = "0009"
down_revision = "0008"


def upgrade() -> None:
    op.execute("ALTER TABLE users DROP CONSTRAINT users_role_check")
    op.execute("ALTER TABLE users ADD CONSTRAINT users_role_check "
               "CHECK (role IN ('viewer','auditor','operator','approver','admin'))")


def downgrade() -> None:
    raise NotImplementedError
