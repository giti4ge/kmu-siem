"""Benachrichtigungskanäle: Einstellungen, Test, Zustand."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import notify
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["notify"], prefix="/api/notifications")


class SettingsIn(BaseModel):
    email_enabled: bool = False
    smtp_host: str = Field("", max_length=253)
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_user: str = Field("", max_length=200)
    smtp_password: str | None = Field(None, max_length=200)
    mail_from: str = Field("", max_length=254)
    mail_to: list[str] = Field(default_factory=list, max_length=20)
    teams_enabled: bool = False
    teams_url: str | None = Field(None, max_length=2000)
    min_severity: Literal["low", "medium", "high", "critical"] = "high"


class TestIn(BaseModel):
    channel: Literal["email", "teams"]


def _view(request: Request) -> dict[str, Any]:
    store: notify.Store = request.app.state.notify_store
    return {"config": store.config(), "state": store.state()}


@router.get("")
def get_settings(request: Request, ctx: Ctx = Depends(require("system:read"))) -> dict:
    return _view(request)


@router.put("")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("system:write"))) -> dict:
    store: notify.Store = request.app.state.notify_store
    cfg = body.model_dump(exclude={"smtp_password", "teams_url"})
    try:
        store.save(cfg, body.smtp_password or None, body.teams_url or None)
    except notify.NotifyError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "notify_storage_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="notify.settings", target="", ip=ctx.ip,
                                details={"email": body.email_enabled, "teams": body.teams_enabled,
                                         "password_changed": bool(body.smtp_password),
                                         "webhook_changed": bool(body.teams_url), "min_severity": body.min_severity})
    return _view(request)


@router.post("/test")
def test_channel(body: TestIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("system:write"))) -> dict:
    store: notify.Store = request.app.state.notify_store
    cfg = store.config()
    subject, text = "[KMU-SIEM] Testnachricht", "Dies ist eine Testnachricht der Alarmierung."
    try:
        if body.channel == "email":
            notify.send_email(cfg, store.secret("smtp_password"), subject, text)
        else:
            notify.send_teams(store.secret("teams_url"), subject, text, "low")
    except notify.NotifyError as exc:
        store.record(body.channel, False, exc.code)
        state(request).audit.append(db, actor=ctx.user.username, action="notify.test", target=body.channel,
                                    outcome="failure", ip=ctx.ip, details={"error": exc.code})
        raise error(502, exc.code) from exc
    store.record(body.channel, True)
    state(request).audit.append(db, actor=ctx.user.username, action="notify.test", target=body.channel, ip=ctx.ip,
                                details={})
    return {"ok": True}
