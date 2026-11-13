"""Windows-Anbindung (OpenWEC): Einstellungen, Onboarding-Skript, Keytab, Status."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import wec
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["wec"], prefix="/api/wec")


class SettingsIn(BaseModel):
    domain: str = Field(max_length=253)
    fqdn: str = Field(max_length=253)
    service_account: str = Field(default="svc-siem-wec", max_length=20)
    roles: dict[str, list[str]] = Field(default_factory=dict)


class KeytabIn(BaseModel):
    keytab_b64: str = Field(max_length=16_384)


def _status(request: Request, settings: dict[str, Any]) -> dict[str, Any]:
    wec_dir = state(request).settings.wec_dir
    configured = bool(settings["domain"] and settings["fqdn"])
    return {
        "settings": settings,
        "configured": configured,
        "keytab": wec.keytab_present(wec_dir),
        "principal": wec.principal(settings) if configured else None,
        "roles": [{"role": r, "uri": wec.role_uri(r), "ous": settings["roles"].get(r, [])} for r in wec.ROLES],
        "machines": wec.machine_count() if configured else None,
        "audit_policy": wec.recommended_audit_policy(),
    }


@router.get("")
def get_wec(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict:
    return _status(request, wec.load_settings(state(request).settings.wec_dir))


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("sources:write"))) -> dict:
    st = state(request)
    try:
        settings = wec.validate_settings(body.model_dump())
    except wec.WecError as exc:
        raise error(400, exc.code) from exc
    try:
        wec.write_all(st.settings.wec_dir, settings)
    except OSError as exc:
        raise error(503, "wec_storage_unavailable") from exc
    st.audit.append(db, actor=ctx.user.username, action="wec.settings", target=settings["fqdn"], ip=ctx.ip,
                    details={"domain": settings["domain"], "roles": {r: len(o) for r, o in settings["roles"].items()}})
    return _status(request, settings)


@router.get("/script")
def get_script(request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("sources:write"))) -> Response:
    settings = wec.load_settings(state(request).settings.wec_dir)
    if not (settings["domain"] and settings["fqdn"]):
        raise error(409, "wec_not_configured")
    script = wec.render_script(settings)
    digest = wec.script_sha256(script)
    state(request).audit.append(db, actor=ctx.user.username, action="wec.script", target=settings["fqdn"],
                                ip=ctx.ip, details={"sha256": digest})
    return Response(
        content="﻿" + script, media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="siem-wec-onboarding.ps1"',
                 "X-Script-SHA256": digest, "Cache-Control": "no-store"})


@router.put("/keytab")
def put_keytab(body: KeytabIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("sources:write"))) -> dict:
    st = state(request)
    settings = wec.load_settings(st.settings.wec_dir)
    if not (settings["domain"] and settings["fqdn"]):
        raise error(409, "wec_not_configured")
    try:
        data = base64.b64decode(body.keytab_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise error(400, "wec_keytab_invalid") from exc
    try:
        wec.check_keytab(data, settings)
    except wec.WecError as exc:
        raise error(400, exc.code) from exc
    try:
        wec.write_all(st.settings.wec_dir, settings)
        wec._write(st.settings.wec_dir / "krb5.keytab", data, 0o640)
    except OSError as exc:
        raise error(503, "wec_storage_unavailable") from exc
    st.audit.append(db, actor=ctx.user.username, action="wec.keytab", target=wec.principal(settings), ip=ctx.ip)
    return _status(request, settings)
