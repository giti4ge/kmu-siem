"""Active Response: Einstellungen, aktive Sperren, manuelles Sperren/Entsperren."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import active_response as ar
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["active-response"], prefix="/api/ar")


class SettingsIn(BaseModel):
    enabled: bool = False
    auto: bool = False
    group: str = Field(ar.GROUP_DEFAULT, max_length=35)
    hours: int = Field(24, ge=1, le=720)
    protected: list[str] = Field(default_factory=list, max_length=50)
    token: str | None = Field(None, max_length=200)


class BlockIn(BaseModel):
    ip: str = Field(max_length=45)
    hours: int | None = Field(None, ge=1, le=720)
    reason: str = Field("manuell", max_length=200)


def _view(request: Request) -> dict[str, Any]:
    st: ar.Store = request.app.state.ar_store
    return {"config": st.config(), "blocks": st.blocks(), "max": ar.MAX_ACTIVE}


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("alerts:read"))) -> dict:
    return _view(request)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("system:write"))) -> dict:
    try:
        request.app.state.ar_store.save(body.model_dump(exclude={"token"}), body.token or None)
    except ar.ARError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "ar_storage_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="ar.settings", target=body.group, ip=ctx.ip,
                                details={"enabled": body.enabled, "auto": body.auto, "token_changed": bool(body.token)})
    return _view(request)


@router.post("/block")
def post_block(body: BlockIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("alerts:write"))) -> dict:
    try:
        entry = ar.block(request.app.state.ar_store, request.app.state.forti_store, body.ip, body.hours, body.reason,
                         ctx.user.username)
    except ar.ARError as exc:
        state(request).audit.append(db, actor=ctx.user.username, action="ar.block", target=body.ip[:45], ip=ctx.ip,
                                    outcome="failure", details={"error": exc.code})
        raise error(409 if exc.code in ("ar_disabled", "ar_protected_ip", "ar_limit_reached") else 502
                    if exc.code.startswith(("ar_forti", "fortigate", "ar_group")) else 400, exc.code) from exc
    state(request).audit.append(db, actor=ctx.user.username, action="ar.block", target=entry["ip"], ip=ctx.ip,
                                details={"until": entry["until"], "reason": entry["reason"]})
    return _view(request)


@router.delete("/block/{ip}")
def delete_block(ip: str, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("alerts:write"))) -> dict:
    try:
        found = ar.unblock(request.app.state.ar_store, request.app.state.forti_store, ip)
    except ar.ARError as exc:
        raise error(502, exc.code) from exc
    if not found:
        raise error(404, "ar_not_found")
    state(request).audit.append(db, actor=ctx.user.username, action="ar.unblock", target=ip, ip=ctx.ip, details={})
    return _view(request)
