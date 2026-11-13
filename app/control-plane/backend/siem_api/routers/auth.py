"""Anmeldung: Kennwort, TOTP (Einrichtung/Prüfung), Kennwortwechsel, Abmeldung."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..db import as_utc, utcnow
from ..deps import Ctx, any_stage, client_ip, error, get_db, stages, state
from ..models import User
from ..schemas import CodeIn, LoginIn, MeOut, PasswordChangeIn, TotpSetupOut, UserOut
from ..security import crypto, passwords, rbac, sessions, totp
from ..security.sessions import STAGE_MFA_ENROLL, STAGE_MFA_VERIFY, STAGE_OK, STAGE_PASSWORD_CHANGE

router = APIRouter(prefix="/api/auth", tags=["auth"])


def me_out(ctx_user: User, sess, stage: str) -> MeOut:
    perms = sorted(rbac.user_permissions(ctx_user.roles)) if stage == STAGE_OK else []
    return MeOut(user=UserOut.model_validate(ctx_user), stage=stage, permissions=perms, csrf_token=sess.csrf_token)


def _set_cookie(request: Request, response: Response, token: str) -> None:
    st = state(request)
    response.set_cookie(
        sessions.COOKIE_NAME, token, httponly=True, secure=st.settings.cookie_secure, samesite="strict",
        path="/", max_age=st.settings.session_max_hours * 3600,
    )


def _register_failure(request: Request, db: DbSession, user: User) -> None:
    """Fehlversuch zählen; ab Schwelle progressive Sperre (1, 2, 4 … Minuten, gedeckelt)."""
    st = state(request)
    user.failed_logins += 1
    over = user.failed_logins - st.settings.lockout_threshold
    if over >= 0:
        minutes = min(2 ** over, st.settings.lockout_max_minutes)
        user.locked_until = utcnow() + timedelta(minutes=minutes)
        st.audit.append(db, actor=user.username, action="auth.locked", target=user.username,
                        outcome="failure", ip=client_ip(request),
                        details={"failed_logins": user.failed_logins, "minutes": minutes}, commit=False)
    db.commit()
    st.audit.sync_head(db)


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: DbSession = Depends(get_db)) -> MeOut:
    st = state(request)
    ip = client_ip(request)
    user = db.scalars(select(User).where(User.username == body.username)).first()
    # Kennwort immer prüfen (auch bei unbekanntem/gesperrtem Konto) – gleiche Laufzeit
    valid = passwords.verify_password(user.password_hash if user else None, body.password)
    locked = bool(user and user.locked_until and as_utc(user.locked_until) > utcnow())
    if user is None or not user.enabled or locked or not valid:
        reason = "unknown_user" if user is None else "disabled" if not user.enabled else \
            "locked" if locked else "bad_password"
        st.audit.append(db, actor=body.username, action="auth.login", target=body.username, outcome="failure",
                        ip=ip, details={"reason": reason})
        if user is not None and reason == "bad_password":
            _register_failure(request, db, user)
        # Einheitliche Antwort: kein Hinweis, ob das Konto existiert oder gesperrt ist
        raise error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)
    mfa_passed = not user.totp_enabled
    if mfa_passed:
        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = utcnow()
    token, sess = sessions.create(db, user, mfa_passed=mfa_passed, ip=ip,
                                  user_agent=request.headers.get("user-agent", ""))
    db.commit()
    stage = sessions.stage(sess)
    st.audit.append(db, actor=user.username, action="auth.login", target=user.username, ip=ip,
                    details={"stage": stage})
    _set_cookie(request, response, token)
    return me_out(user, sess, stage)


@router.post("/totp/verify", response_model=MeOut)
def totp_verify(body: CodeIn, request: Request, ctx: Ctx = Depends(stages(STAGE_MFA_VERIFY)),
                db: DbSession = Depends(get_db)) -> MeOut:
    st = state(request)
    user = db.get(User, ctx.user.id)
    sess = db.merge(ctx.session)
    if user.locked_until and as_utc(user.locked_until) > utcnow():
        raise error(status.HTTP_401_UNAUTHORIZED, "invalid_code")
    secret = crypto.decrypt(st.keys.master_key, user.totp_secret_enc, f"totp:{user.id}")
    step = totp.verify(secret, body.code, user.totp_last_step)
    if step is None:
        st.audit.append(db, actor=user.username, action="auth.totp", target=user.username, outcome="failure",
                        ip=ctx.ip)
        _register_failure(request, db, user)
        raise error(status.HTTP_401_UNAUTHORIZED, "invalid_code")
    user.totp_last_step = step
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    sess.mfa_passed = True
    db.commit()
    st.audit.append(db, actor=user.username, action="auth.totp", target=user.username, ip=ctx.ip)
    return me_out(user, sess, sessions.stage(sess))


@router.post("/totp/setup", response_model=TotpSetupOut)
def totp_setup(request: Request, ctx: Ctx = Depends(stages(STAGE_MFA_ENROLL, STAGE_OK)),
               db: DbSession = Depends(get_db)) -> TotpSetupOut:
    """Neues TOTP-Geheimnis erzeugen (noch nicht aktiv, erst nach /totp/enable)."""
    st = state(request)
    user = db.get(User, ctx.user.id)
    if user.totp_enabled:
        raise error(status.HTTP_409_CONFLICT, "totp_already_enabled")
    secret = totp.new_secret()
    user.totp_secret_enc = crypto.encrypt(st.keys.master_key, secret, f"totp:{user.id}")
    db.commit()
    return TotpSetupOut(secret=secret, uri=totp.provisioning_uri(secret, user.username, st.settings.totp_issuer))


@router.post("/totp/enable", response_model=MeOut)
def totp_enable(body: CodeIn, request: Request, ctx: Ctx = Depends(stages(STAGE_MFA_ENROLL, STAGE_OK)),
                db: DbSession = Depends(get_db)) -> MeOut:
    st = state(request)
    user = db.get(User, ctx.user.id)
    sess = db.merge(ctx.session)
    if user.totp_enabled:
        raise error(status.HTTP_409_CONFLICT, "totp_already_enabled")
    if not user.totp_secret_enc:
        raise error(status.HTTP_409_CONFLICT, "totp_not_set_up")
    secret = crypto.decrypt(st.keys.master_key, user.totp_secret_enc, f"totp:{user.id}")
    step = totp.verify(secret, body.code, None)
    if step is None:
        raise error(status.HTTP_400_BAD_REQUEST, "invalid_code")
    user.totp_enabled = True
    user.totp_last_step = step
    sess.mfa_passed = True
    db.commit()
    st.audit.append(db, actor=user.username, action="auth.totp_enabled", target=user.username, ip=ctx.ip)
    return me_out(user, sess, sessions.stage(sess))


@router.post("/password", response_model=MeOut)
def change_password(body: PasswordChangeIn, request: Request,
                    ctx: Ctx = Depends(stages(STAGE_PASSWORD_CHANGE, STAGE_MFA_ENROLL, STAGE_OK)),
                    db: DbSession = Depends(get_db)) -> MeOut:
    st = state(request)
    user = db.get(User, ctx.user.id)
    sess = db.merge(ctx.session)
    if not passwords.verify_password(user.password_hash, body.current_password):
        st.audit.append(db, actor=user.username, action="auth.password_change", target=user.username,
                        outcome="failure", ip=ctx.ip, details={"reason": "bad_password"})
        _register_failure(request, db, user)
        raise error(status.HTTP_400_BAD_REQUEST, "invalid_current_password")
    if body.new_password == body.current_password:
        raise error(status.HTTP_400_BAD_REQUEST, "password_unchanged")
    try:
        passwords.check_policy(body.new_password, user.username, [user.display_name, user.email])
    except passwords.PolicyError as exc:
        raise error(status.HTTP_400_BAD_REQUEST, exc.args[0]) from exc
    user.password_hash = passwords.hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    # Alle anderen Sitzungen des Benutzers beenden
    sessions.revoke_user_sessions(db, user.id, except_id=sess.id)
    db.commit()
    st.audit.append(db, actor=user.username, action="auth.password_change", target=user.username, ip=ctx.ip)
    return me_out(user, sess, sessions.stage(sess))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, ctx: Ctx = Depends(any_stage),
           db: DbSession = Depends(get_db)) -> Response:
    st = state(request)
    sess = db.merge(ctx.session)
    db.delete(sess)
    db.commit()
    st.audit.append(db, actor=ctx.user.username, action="auth.logout", target=ctx.user.username, ip=ctx.ip)
    response.delete_cookie(sessions.COOKIE_NAME, path="/", secure=st.settings.cookie_secure, samesite="strict")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=MeOut)
def me(ctx: Ctx = Depends(any_stage)) -> MeOut:
    return me_out(ctx.user, ctx.session, ctx.stage)
