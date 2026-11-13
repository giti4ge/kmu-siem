"""Datenmodell der Config-DB (SQLAlchemy 2). Änderungen nur mit Alembic-Migration."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    # Vordefinierte Rollen sind nicht änderbar/löschbar
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    # MFA (TOTP) verpflichtend für Mitglieder dieser Rolle
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    # Berechtigungen als Liste "modul:aktion" (rbac.PERMISSIONS)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Datenbereiche: erlaubte Log-Kategorien (leer = alle), Feld-Maskierung – Durchsetzung ab Phase 3/6
    data_scope: Mapped[dict] = mapped_column(JSON, default=dict)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    language: Mapped[str] = mapped_column(String(2), default="de")
    password_hash: Mapped[str] = mapped_column(String(255))
    # Kennwort muss bei der nächsten Anmeldung geändert werden (z. B. nach Zurücksetzen)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # TOTP-Geheimnis AES-GCM-verschlüsselt (crypto.py); totp_enabled erst nach Bestätigung
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Schutz gegen Wiederverwendung eines TOTP-Codes (letzter akzeptierter Zeitschritt)
    totp_last_step: Mapped[int | None] = mapped_column(Integer)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    roles: Mapped[list[Role]] = relationship(secondary="user_roles", lazy="selectin")


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)


class Session(Base):
    """Serverseitige Sitzung. Im Cookie steht nur das Token, in der DB nur dessen SHA-256."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # Zweiter Faktor erledigt (bzw. für den Benutzer nicht nötig)
    mfa_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")

    user: Mapped[User] = relationship(lazy="joined")


class AuditEntry(Base):
    """Audit-Log mit HMAC-Hash-Kette (audit.py). Nur anhängen, nie ändern."""

    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[str] = mapped_column(String(40))  # ISO-8601 UTC, Teil des Hashes
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")  # kanonisches JSON
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Secret(Base):
    """Geheimnisse (SMTP, Teams-URL, API-Keys …) AES-256-GCM-verschlüsselt."""

    __tablename__ = "secrets"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_enc: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
