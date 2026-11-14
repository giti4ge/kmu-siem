"""Update-Prüfung: Einstellungen und Abfrage neuer Versionen."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import __version__, updates
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["updates"], prefix="/api/updates")


class SettingsIn(BaseModel):
    repo: str = Field(updates.DEFAULT_REPO, max_length=201)
    channel: Literal["stable", "beta"] = "stable"
    token: str | None = Field(None, max_length=300)


def _view(request: Request) -> dict[str, Any]:
    return {"current": __version__, "config": request.app.state.update_store.config()}


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("system:read"))) -> dict:
    return _view(request)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, db: DbSession = Depends(get_db),
                 ctx: Ctx = Depends(require("system:write"))) -> dict:
    try:
        request.app.state.update_store.save(body.repo.strip(), body.channel, body.token or None)
    except updates.UpdateError as exc:
        raise error(400, exc.code) from exc
    except OSError as exc:
        raise error(503, "update_storage_unavailable") from exc
    state(request).audit.append(db, actor=ctx.user.username, action="updates.settings", target=body.repo, ip=ctx.ip,
                                details={"channel": body.channel, "token_changed": bool(body.token)})
    return _view(request)


@router.post("/check")
def check_now(request: Request, ctx: Ctx = Depends(require("system:write"))) -> dict:
    try:
        return updates.check(request.app.state.update_store)
    except updates.UpdateError as exc:
        raise error(502, exc.code) from exc
