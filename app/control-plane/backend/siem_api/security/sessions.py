"""Serverseitige Sitzungen (Cookie, HttpOnly/Secure/SameSite=Strict) und Anmeldestufen."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from ..config import Settings
from ..db import as_utc, utcnow
from ..models import Session, User
from . import rbac

COOKIE_NAME = "siem_session"
CSRF_HEADER = "X-CSRF-Token"

# Anmeldestufen: erst bei "ok" sind fachliche Endpunkte erreichbar
STAGE_OK = "ok"
STAGE_MFA_VERIFY = "mfa_verify"        # TOTP-Code eingeben
STAGE_PASSWORD_CHANGE = "password_change"  # noqa: S105 – Kennwort muss geändert werden (kein Geheimnis)
STAGE_MFA_ENROLL = "mfa_enroll"        # Rolle verlangt MFA, TOTP noch nicht eingerichtet


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db: DbSession, user: User, *, mfa_passed: bool, ip: str, user_agent: str) -> tuple[str, Session]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    sess = Session(
        token_hash=_hash(token), csrf_token=secrets.token_urlsafe(32), user_id=user.id,
        mfa_passed=mfa_passed, created_at=now, last_seen_at=now,
        ip=ip[:64], user_agent=user_agent[:255],
    )
    db.add(sess)
    db.flush()
    return token, sess


def lookup(db: DbSession, token: str | None, settings: Settings) -> Session | None:
    """Gültige Sitzung zum Token; abgelaufene werden entfernt. Aktualisiert last_seen_at."""
    if not token or len(token) > 128:
        return None
    sess = db.scalars(select(Session).where(Session.token_hash == _hash(token))).first()
    if sess is None:
        return None
    now = utcnow()
    idle = now - as_utc(sess.last_seen_at) > timedelta(minutes=settings.session_idle_minutes)
    too_old = now - as_utc(sess.created_at) > timedelta(hours=settings.session_max_hours)
    if idle or too_old or not sess.user.enabled:
        db.delete(sess)
        db.commit()
        return None
    sess.last_seen_at = now
    db.commit()
    return sess


def revoke_user_sessions(db: DbSession, user_id: int, except_id: int | None = None) -> None:
    stmt = delete(Session).where(Session.user_id == user_id)
    if except_id is not None:
        stmt = stmt.where(Session.id != except_id)
    db.execute(stmt)


def stage(sess: Session) -> str:
    user = sess.user
    if user.totp_enabled and not sess.mfa_passed:
        return STAGE_MFA_VERIFY
    if user.must_change_password:
        return STAGE_PASSWORD_CHANGE
    if rbac.mfa_required(user.roles) and not user.totp_enabled:
        return STAGE_MFA_ENROLL
    return STAGE_OK


def check_csrf(sess: Session, header_value: str | None) -> bool:
    return bool(header_value) and secrets.compare_digest(sess.csrf_token, header_value)
