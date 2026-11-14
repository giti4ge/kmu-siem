"""Sophos-Central-Anbindung: Einstellungen, Verbindungstest, Status, sofortiger Abruf."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import sophos
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["sophos"], prefix="/api/sophos")


class SettingsIn(BaseModel):
    enabled: bool
    client_id: str = Field(max_length=100, pattern=r"^[A-Za-z0-9-]*$")
    client_secret: str | None = Field(default=None, max_length=200)
    mode: Literal["auto", "datalake", "siem"] = "auto"


def _status(request: Request) -> dict[str, Any]:
    store: sophos.Store = request.app.state.sophos_store
    st = store.state()
    return {"config": store.config(), "last_run": st.get("last_run"), "last_mode": st.get("last_mode"),
            "interval_minutes": sophos.INTERVAL_SECONDS // 60}


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict:
    return _status(request)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("sources:write"))) -> dict:
    store: sophos.Store = request.app.state.sophos_store
    if body.enabled and not body.client_id:
        raise error(400, "sophos_not_configured")
    try:
        store.save(enabled=body.enabled, client_id=body.client_id, mode=body.mode,
                   client_secret=body.client_secret or None)
    except OSError as exc:
        raise error(503, "sophos_storage_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="sophos.settings", target=body.client_id,
                                ip=ctx.ip, details={"enabled": body.enabled, "mode": body.mode,
                                                    "secret_changed": bool(body.client_secret)})
    request.app.state.sophos_poller.trigger.set()
    return _status(request)


@router.post("/test")
def test_connection(request: Request, ctx: Ctx = Depends(require("sources:write"))) -> dict:
    """Anmeldung, Mandant und Data-Lake-Berechtigung prüfen (ohne Ereignisse abzurufen)."""
    store: sophos.Store = request.app.state.sophos_store
    cfg = store.config()
    try:
        c = sophos.Central(cfg["client_id"], store.secret())
        c.connect()
        try:
            c.http("GET", f"{c.api}/xdr-query/v1/queries/runs?pageSize=1", headers=c._h())
            datalake = True
        except sophos.NoLicense:
            datalake = False
    except sophos.SophosError as exc:
        raise error(502 if exc.code != "sophos_not_configured" else 409, exc.code) from exc
    return {"ok": True, "tenant": c.tenant, "datalake": datalake}


@router.post("/run")
def run_now(request: Request, ctx: Ctx = Depends(require("sources:write"))) -> dict:
    request.app.state.sophos_poller.trigger.set()
    return _status(request)
