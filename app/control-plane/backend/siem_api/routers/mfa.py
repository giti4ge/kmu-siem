"""Mein Konto: mehrere MFA-Geräte (TOTP) verwalten.

Das erste Gerät liegt in ``users.totp_*`` (Einrichtung über /api/auth/totp/*); weitere Geräte stehen in ``mfa_devices``.
Bei der Anmeldung genügt der Code eines beliebigen aktiven Geräts. Das Löschen verlangt das Kennwort; das letzte
Gerät kann nicht entfernt werden (Zurücksetzen der MFA ist Sache der Administration).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..db import utcnow
from ..deps import Ctx, authenticated, error, get_db, state
from ..models import MfaDevice, User
from ..schemas import CodeIn, Strict, TotpSetupOut
from ..security import crypto, passwords, totp

router = APIRouter(tags=["mfa"], prefix="/api/auth/mfa")
PRIMARY = 0  # Kennung des ersten Geräts in der Liste
MAX_DEVICES = 5


class DeviceIn(Strict):
    name: str = Field(min_length=1, max_length=64)


class DeleteIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)


def _active(db: DbSession, user: User) -> list[MfaDevice]:
    return list(db.scalars(select(MfaDevice).where(MfaDevice.user_id == user.id, MfaDevice.enabled.is_(True))
                           .order_by(MfaDevice.id)))


def _view(db: DbSession, user: User) -> dict:
    out = []
    if user.totp_enabled:
        out.append({"id": PRIMARY, "name": "", "primary": True, "created_at": None})
    for d in _active(db, user):
        out.append({"id": d.id, "name": d.name, "primary": False, "created_at": d.created_at.isoformat()})
    return {"devices": out, "max": MAX_DEVICES}


@router.get("/devices")
def devices(ctx: Ctx = Depends(authenticated), db: DbSession = Depends(get_db)) -> dict:
    return _view(db, db.get(User, ctx.user.id))


@router.post("/devices", response_model=TotpSetupOut)
def add_device(body: DeviceIn, request: Request, ctx: Ctx = Depends(authenticated),
               db: DbSession = Depends(get_db)) -> TotpSetupOut:
    """Neues Gerät vormerken (noch nicht aktiv); aktiv wird es mit /devices/enable."""
    st = state(request)
    user = db.get(User, ctx.user.id)
    if not user.totp_enabled:
        raise error(status.HTTP_409_CONFLICT, "totp_not_set_up")
    if len(_view(db, user)["devices"]) >= MAX_DEVICES:
        raise error(status.HTTP_409_CONFLICT, "mfa_device_limit")
    db.query(MfaDevice).filter_by(user_id=user.id, enabled=False).delete()  # nur eine offene Einrichtung
    secret = totp.new_secret()
    dev = MfaDevice(user_id=user.id, name=body.name.strip(), secret_enc=b"", enabled=False, created_at=utcnow())
    db.add(dev)
    db.flush()
    dev.secret_enc = crypto.encrypt(st.keys.master_key, secret, f"mfa:{dev.id}")
    db.commit()
    return TotpSetupOut(secret=secret, uri=totp.provisioning_uri(secret, user.username, st.settings.totp_issuer))


@router.post("/devices/enable")
def enable_device(body: CodeIn, request: Request, ctx: Ctx = Depends(authenticated),
                  db: DbSession = Depends(get_db)) -> dict:
    st = state(request)
    user = db.get(User, ctx.user.id)
    dev = db.scalars(select(MfaDevice).where(MfaDevice.user_id == user.id, MfaDevice.enabled.is_(False))).first()
    if dev is None:
        raise error(status.HTTP_409_CONFLICT, "totp_not_set_up")
    secret = crypto.decrypt(st.keys.master_key, dev.secret_enc, f"mfa:{dev.id}")
    step = totp.verify(secret, body.code, None)
    if step is None:
        raise error(status.HTTP_400_BAD_REQUEST, "invalid_code")
    dev.enabled, dev.last_step = True, step
    db.commit()
    st.audit.append(db, actor=user.username, action="auth.mfa_device_added", target=user.username, ip=ctx.ip,
                    details={"name": dev.name})
    return _view(db, user)


@router.post("/devices/{device_id}/delete")
def delete_device(device_id: int, body: DeleteIn, request: Request, ctx: Ctx = Depends(authenticated),
                  db: DbSession = Depends(get_db)) -> dict:
    st = state(request)
    user = db.get(User, ctx.user.id)
    if not passwords.verify_password(user.password_hash, body.current_password):
        st.audit.append(db, actor=user.username, action="auth.mfa_device_removed", target=user.username,
                        outcome="failure", ip=ctx.ip, details={"reason": "bad_password"})
        raise error(status.HTTP_400_BAD_REQUEST, "invalid_current_password")
    extra = _active(db, user)
    name = ""
    if device_id == PRIMARY:
        if not extra:
            raise error(status.HTTP_409_CONFLICT, "mfa_last_device")
        nxt = extra[0]  # das nächste Gerät rückt an die erste Stelle
        secret = crypto.decrypt(st.keys.master_key, nxt.secret_enc, f"mfa:{nxt.id}")
        user.totp_secret_enc = crypto.encrypt(st.keys.master_key, secret, f"totp:{user.id}")
        user.totp_last_step = nxt.last_step
        db.delete(nxt)
    else:
        dev = next((d for d in extra if d.id == device_id), None)
        if dev is None:
            raise error(status.HTTP_404_NOT_FOUND, "mfa_device_not_found")
        name = dev.name
        db.delete(dev)
    db.commit()
    st.audit.append(db, actor=user.username, action="auth.mfa_device_removed", target=user.username, ip=ctx.ip,
                    details={"name": name})
    return _view(db, user)
