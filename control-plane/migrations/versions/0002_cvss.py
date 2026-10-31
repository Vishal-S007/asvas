"""CVSS 4.0 base vector and score on findings (DA-09).

Revision ID: 0002
"""
from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    op.execute("ALTER TABLE findings ADD COLUMN cvss_vector TEXT, ADD COLUMN cvss_score NUMERIC(3,1), "
               "ADD COLUMN cvss_severity TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN cvss_vector, DROP COLUMN cvss_score, DROP COLUMN cvss_severity")
