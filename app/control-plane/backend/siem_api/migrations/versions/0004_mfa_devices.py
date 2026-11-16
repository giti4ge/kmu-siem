"""Weitere MFA-Geräte je Benutzer

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mfa_devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("secret_enc", sa.LargeBinary, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("last_step", sa.Integer),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
