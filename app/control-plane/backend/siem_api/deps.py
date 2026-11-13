"""FastAPI-Abhängigkeiten: DB-Sitzung, Anmeldung, Anmeldestufe, CSRF, Berechtigungen."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DbSession

from .audit import AuditLog
from .config import Settings
from .db import Database
from .models import Session, User
from .security import rbac, sessions
from .security.keys import KeyRing

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class AppState:
    settings: Settings
    db: Database
    keys: KeyRing
    audit: AuditLog


def state(request: Request) -> AppState:
    return request.app.state.siem


def get_db(request: Request) -> Iterator[DbSession]:
    yield from state(request).db.session()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def error(code: int, key: str) -> HTTPException:
    """Fehler mit maschinenlesbarem Schlüssel (Übersetzung im Frontend)."""
    return HTTPException(status_code=code, detail={"error": key})


@dataclass
class Ctx:
    session: Session
    user: User
    permissions: set[str]
    stage: str
    ip: str


def _context(request: Request, db: DbSession, allowed_stages: tuple[str, ...]) -> Ctx:
    st = state(request)
    sess = sessions.lookup(db, request.cookies.get(sessions.COOKIE_NAME), st.settings)
    if sess is None:
        raise error(status.HTTP_401_UNAUTHORIZED, "not_authenticated")
    if request.method not in SAFE_METHODS and not sessions.check_csrf(sess, request.headers.get(sessions.CSRF_HEADER)):
        raise error(status.HTTP_403_FORBIDDEN, "csrf_failed")
    current = sessions.stage(sess)
    if current not in allowed_stages:
        raise error(status.HTTP_403_FORBIDDEN, f"stage_{current}")
    return Ctx(sess, sess.user, rbac.user_permissions(sess.user.roles), current, client_ip(request))


def any_stage(request: Request, db: DbSession = Depends(get_db)) -> Ctx:
    """Angemeldet, Anmeldung aber evtl. noch nicht abgeschlossen (für /me, /logout)."""
    return _context(request, db, (sessions.STAGE_OK, sessions.STAGE_MFA_VERIFY,
                                  sessions.STAGE_PASSWORD_CHANGE, sessions.STAGE_MFA_ENROLL))


def stages(*allowed: str) -> Callable[..., Ctx]:
    def dep(request: Request, db: DbSession = Depends(get_db)) -> Ctx:
        return _context(request, db, allowed)
    return dep


def authenticated(request: Request, db: DbSession = Depends(get_db)) -> Ctx:
    return _context(request, db, (sessions.STAGE_OK,))


def require(permission: str) -> Callable[..., Ctx]:
    """Endpunkt nur mit vollständiger Anmeldung und der Berechtigung `modul:aktion`."""
    if permission not in rbac.PERMISSIONS:
        raise ValueError(f"Unbekannte Berechtigung {permission}")

    def dep(ctx: Ctx = Depends(authenticated)) -> Ctx:
        if permission not in ctx.permissions:
            raise error(status.HTTP_403_FORBIDDEN, "forbidden")
        return ctx
    dep.permission = permission  # für die Prüfung der Rollen-Matrix in den Tests
    return dep
