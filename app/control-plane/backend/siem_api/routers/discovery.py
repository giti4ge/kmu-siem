"""Discovery-Scanner und MIB-Import (Quellen)."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import discovery as dc
from .. import mibs
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["discovery"], prefix="/api")


class ScanIn(BaseModel):
    network: str = Field(max_length=50)


@router.get("/discovery")
def get_scan(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict[str, Any]:
    return request.app.state.scanner.state()


@router.post("/discovery")
def start_scan(body: ScanIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("sources:write"))) -> dict[str, Any]:
    try:
        res = request.app.state.scanner.start(body.network, ctx.user.username)
    except dc.DiscoveryError as exc:
        raise error(409 if exc.code == "discovery_busy" else 422, exc.code) from None
    state(request).audit.append(db, actor=ctx.user.username, action="discovery.scan", target=body.network,
                                ip=ctx.ip, details={"hosts": res.get("hosts")})
    return res


class MibIn(BaseModel):
    filename: str = Field(max_length=64)
    content: str | None = Field(default=None, max_length=mibs.MAX_FILE)
    content_b64: str | None = Field(default=None, max_length=4 * mibs.MAX_ZIP_TOTAL // 3 + 8)


@router.get("/snmp/mibs")
def list_mibs(request: Request, q: str = "", ctx: Ctx = Depends(require("sources:read"))) -> dict[str, Any]:
    store = request.app.state.mibs
    return {"modules": store.modules(), "matches": store.search(q) if q else []}


@router.post("/snmp/mibs")
def import_mib(body: MibIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("sources:write"))) -> dict[str, Any]:
    store = request.app.state.mibs
    try:
        if body.content_b64:
            raw = base64.b64decode(body.content_b64, validate=True)
        elif body.content is not None:
            raw = body.content.encode()
        else:
            raise error(422, "mib_invalid_file")
        if body.filename.lower().endswith(".zip") or raw[:2] == b"PK":
            res: Any = store.add_zip(raw)
        else:
            res = store.add(body.filename, raw)
    except binascii.Error:
        raise error(422, "mib_invalid_file") from None
    except mibs.MibError as exc:
        raise error(422, exc.code) from None
    state(request).audit.append(db, actor=ctx.user.username, action="snmp.mib_import", target=body.filename[:64],
                                ip=ctx.ip, details={"result": res if isinstance(res, dict) else {"files": len(res)}})
    return {"result": res, "modules": store.modules()}


@router.delete("/snmp/mibs/{module}")
def delete_mib(module: str, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("sources:write"))) -> dict[str, Any]:
    if not request.app.state.mibs.remove(module):
        raise error(404, "mib_not_found")
    state(request).audit.append(db, actor=ctx.user.username, action="snmp.mib_delete", target=module, ip=ctx.ip,
                                details={})
    return {"modules": request.app.state.mibs.modules()}
