"""Geräteliste (Logquellen) verwalten; die Liste steuert das Parser-Routing in Vector."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from .. import devices as dev
from .. import hostd
from ..db import utcnow
from ..deps import Ctx, error, get_db, require, state
from ..models import Device

router = APIRouter(tags=["devices"], prefix="/api/devices")
log = logging.getLogger(__name__)


class DeviceIn(BaseModel):
    ip: str = Field(max_length=45)
    name: str = Field(max_length=64)
    type: str = Field(max_length=32)
    note: str = Field(default="", max_length=255)


def _out(d: Device) -> dict[str, Any]:
    return {"id": d.id, "ip": d.ip, "name": d.name, "type": d.type, "note": d.note}


def _apply(request: Request, db: DbSession, actor: str) -> bool:
    """devices.csv schreiben und Vector neu laden; False, wenn das Neuladen nicht möglich war."""
    st = state(request)
    pairs = [(d.ip, d.type) for d in db.scalars(select(Device))]
    try:
        dev.write_csv(st.settings.vector_dir, pairs)
    except OSError as exc:
        raise error(503, "wec_storage_unavailable") from exc
    try:
        hostd.call(st.settings.hostd_socket, "vector.reload", {}, actor=f"{actor}@web")
    except (hostd.HostdUnavailable, hostd.HostdRejected):
        log.warning("Vector konnte nicht neu geladen werden")
        return False
    return True


@router.get("")
def list_devices(db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("sources:read"))) -> dict:
    rows = db.scalars(select(Device).order_by(Device.name)).all()
    return {"devices": [_out(d) for d in rows], "types": list(dev.DEVICE_TYPES)}


@router.post("", status_code=201)
def create_device(body: DeviceIn, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("sources:write"))) -> dict:
    try:
        ip, name, typ = dev.validate(body.ip, body.name, body.type)
    except dev.DeviceError as exc:
        raise error(400, exc.code) from exc
    row = Device(ip=ip, name=name, type=typ, note=body.note.strip(), created_at=utcnow())
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise error(409, "device_exists") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="device.create", target=ip, ip=ctx.ip,
                                details={"name": name, "type": typ})
    return {**_out(row), "applied": _apply(request, db, ctx.user.username)}


@router.put("/{device_id}")
def update_device(device_id: int, body: DeviceIn, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("sources:write"))) -> dict:
    row = db.get(Device, device_id)
    if row is None:
        raise error(404, "device_not_found")
    try:
        ip, name, typ = dev.validate(body.ip, body.name, body.type)
    except dev.DeviceError as exc:
        raise error(400, exc.code) from exc
    row.ip, row.name, row.type, row.note = ip, name, typ, body.note.strip()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise error(409, "device_exists") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="device.update", target=ip, ip=ctx.ip,
                                details={"name": name, "type": typ})
    return {**_out(row), "applied": _apply(request, db, ctx.user.username)}


@router.delete("/{device_id}")
def delete_device(device_id: int, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("sources:write"))) -> Response:
    row = db.get(Device, device_id)
    if row is None:
        raise error(404, "device_not_found")
    ip = row.ip
    db.delete(row)
    db.commit()
    state(request).audit.append(db, actor=ctx.user.username, action="device.delete", target=ip, ip=ctx.ip)
    _apply(request, db, ctx.user.username)
    return Response(status_code=204)
