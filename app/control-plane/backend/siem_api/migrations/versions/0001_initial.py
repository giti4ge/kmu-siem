"""Grundschema: Rollen, Benutzer, Sitzungen, Audit-Log, Geheimnisse

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("builtin", sa.Boolean, nullable=False),
        sa.Column("mfa_required", sa.Boolean, nullable=False),
        sa.Column("permissions", sa.JSON, nullable=False),
        sa.Column("data_scope", sa.JSON, nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("language", sa.String(2), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("must_change_password", sa.Boolean, nullable=False),
        sa.Column("password_changed_at", TS),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("totp_secret_enc", sa.LargeBinary),
        sa.Column("totp_enabled", sa.Boolean, nullable=False),
        sa.Column("totp_last_step", sa.Integer),
        sa.Column("failed_logins", sa.Integer, nullable=False),
        sa.Column("locked_until", TS),
        sa.Column("last_login_at", TS),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mfa_passed", sa.Boolean, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_seen_at", TS, nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("user_agent", sa.String(255), nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("ts", sa.String(40), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("details", sa.Text, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("seq"),
    )
    op.create_table(
        "secrets",
        sa.Column("name", sa.String(128), primary_key=True),
        sa.Column("value_enc", sa.LargeBinary, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
    )


def downgrade() -> None:
    for table in ("secrets", "audit_log", "sessions", "user_roles", "users", "roles"):
        op.drop_table(table)
