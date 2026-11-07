"""Planning cost accounting per assessment (PL-09).

Revision ID: 0008
"""
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    op.execute("ALTER TABLE assessments ADD COLUMN cost_usd_micros BIGINT NOT NULL DEFAULT 0")


def downgrade() -> None:
    raise NotImplementedError
