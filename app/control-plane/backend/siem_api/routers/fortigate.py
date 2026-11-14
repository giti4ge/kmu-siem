"""FortiGate-API-Anbindung: Einstellungen, Zertifikat-Fingerabdruck, Verbindungstest, Status."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import fortigate
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["fortigate"], prefix="/api/fortigate")


class SettingsIn(BaseModel):
    enabled: bool
    host: str = Field(max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    vdom: str = Field(default="root", max_length=31)
    tls_pin: str = Field(default="", max_length=95)
    token: str | None = Field(default=None, max_length=200)


class ProbeIn(BaseModel):
    host: str = Field(max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


def _status(request: Request) -> dict[str, Any]:
    store: fortigate.Store = request.app.state.forti_store
    st = store.state()
    return {"config": store.config(), "last_run": st.get("last_run"),
            "interval_minutes": fortigate.INTERVAL_SECONDS // 60}


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict:
    return _status(request)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("sources:write"))) -> dict:
    store: fortigate.Store = request.app.state.forti_store
    if body.enabled and not body.host.strip():
        raise error(400, "fortigate_not_configured")
    try:
        store.save(enabled=body.enabled, host=body.host, port=body.port, vdom=body.vdom, tls_pin=body.tls_pin,
                   token=body.token or None)
    except fortigate.FortiError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "fortigate_storage_unavailable") from exc
    state(request).audit.append(
        db, actor=ctx.user.username, action="fortigate.settings", target=body.host, ip=ctx.ip,
        details={"enabled": body.enabled, "vdom": body.vdom, "pinned": bool(body.tls_pin),
                 "token_changed": bool(body.token)})
    request.app.state.forti_poller.trigger.set()
    return _status(request)


@router.post("/fingerprint")
def probe(body: ProbeIn, ctx: Ctx = Depends(require("sources:write"))) -> dict:
    """Zertifikat-Fingerabdruck abrufen; der Administrator vergleicht ihn mit dem Gerät und übernimmt ihn."""
    try:
        return {"fingerprint": fortigate.fetch_fingerprint(body.host.strip(), body.port)}
    except fortigate.FortiError as exc:
        raise error(502, exc.code) from exc


@router.post("/test")
def test_connection(request: Request, ctx: Ctx = Depends(require("sources:write"))) -> dict:
    store: fortigate.Store = request.app.state.forti_store
    cfg = store.config()
    try:
        arp, dhcp = fortigate.fetch(cfg, store.token())
    except fortigate.FortiError as exc:
        raise error(409 if exc.code == "fortigate_not_configured" else 502, exc.code) from exc
    return {"ok": True, "arp": len(arp), "dhcp": len(dhcp)}


@router.post("/run")
def run_now(request: Request, ctx: Ctx = Depends(require("sources:write"))) -> dict:
    request.app.state.forti_poller.trigger.set()
    return _status(request)
