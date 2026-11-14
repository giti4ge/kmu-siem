"""Konfigurations-Snapshots (FortiGate): liste, jetzt sichern, vergleichen."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DbSession

from .. import fortigate as fg
from .. import snapshots as sn
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["snapshots"], prefix="/api/snapshots")


def fetch_fortigate(store: fg.Store, get=fg.api_get_text):
    cfg = store.config()
    if not cfg["enabled"] or not cfg["host"]:
        raise sn.SnapshotError("snapshot_fortigate_off")
    token = store.token()
    path = f"/api/v2/monitor/system/config/backup?scope=global&vdom={cfg['vdom']}"
    return lambda: get(cfg["host"], cfg["port"], path, token, cfg["tls_pin"])


def take_now(request_app, get=fg.api_get_text) -> dict[str, Any]:
    return request_app.state.snapshots.take(fetch_fortigate(request_app.state.forti_store, get))


@router.get("")
def list_snapshots(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> list[dict[str, Any]]:
    return request.app.state.snapshots.list()


@router.post("")
def take(request: Request, db: DbSession = Depends(get_db),
         ctx: Ctx = Depends(require("sources:write"))) -> dict[str, Any]:
    try:
        res = take_now(request.app)
    except sn.SnapshotError as exc:
        raise error(409, exc.code) from None
    except fg.FortiError as exc:
        raise error(502, exc.code) from None
    state(request).audit.append(db, actor=ctx.user.username, action="snapshot.take", target="fortigate", ip=ctx.ip,
                                details={k: res[k] for k in ("changed", "name") if k in res})
    return res


@router.get("/diff")
def diff(request: Request, a: str = Query(max_length=32), b: str = Query(max_length=32),
         ctx: Ctx = Depends(require("sources:read"))) -> dict[str, Any]:
    try:
        return {"lines": request.app.state.snapshots.diff(a, b)}
    except sn.SnapshotError as exc:
        raise error(404, exc.code) from None
