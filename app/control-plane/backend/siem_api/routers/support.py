"""Support-Zugang per SSH: zeitlich begrenzt, nur Allowlist-Befehle (Aktivierung durch einen Administrator)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import hostd
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["support"], prefix="/api/support")


class EnableIn(BaseModel):
    key: str = Field(min_length=40, max_length=2200)
    hours: int = Field(4, ge=1, le=72)
    source: str = Field(max_length=45)


def _call(request: Request, ctx: Ctx, action: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return hostd.call(state(request).settings.hostd_socket, action, params or {}, actor=f"{ctx.user.username}@web")
    except hostd.HostdUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "hostd_unavailable") from exc
    except hostd.HostdRejected as exc:
        raise error(status.HTTP_400_BAD_REQUEST, "support_invalid") from exc


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("system:read"))) -> dict:
    return _call(request, ctx, "support.status")


@router.post("/enable")
def enable(body: EnableIn, request: Request, db: DbSession = Depends(get_db),
           ctx: Ctx = Depends(require("system:write"))) -> dict:
    res = _call(request, ctx, "support.enable", body.model_dump())
    state(request).audit.append(db, actor=ctx.user.username, action="support.enable", target=body.source, ip=ctx.ip,
                                details={"hours": body.hours})
    return res


@router.post("/disable")
def disable(request: Request, db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("system:write"))) -> dict:
    res = _call(request, ctx, "support.disable")
    state(request).audit.append(db, actor=ctx.user.username, action="support.disable", target="", ip=ctx.ip, details={})
    return res
