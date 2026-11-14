"""Revisionssicheres Archiv: Status, Versiegeln, Integritätsprüfung (Spec 4.14a)."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["archive"], prefix="/api/archive")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class VerifyBody(BaseModel):
    since: str | None = None
    until: str | None = None


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("archive:read"))) -> dict[str, Any]:
    worker = request.app.state.archive_worker
    return {**worker.archive.status(), "worker": worker.state()}


@router.post("/seal")
def seal_now(request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("archive:write"))) -> dict[str, Any]:
    res = request.app.state.archive_worker.run_seal()
    state(request).audit.append(db, actor=ctx.user.username, action="archive.seal", target="archive", ip=ctx.ip,
                                outcome="success" if res["ok"] else "failure", details={})
    return res


@router.post("/verify")
def verify(body: VerifyBody, request: Request, db: DbSession = Depends(get_db),
           ctx: Ctx = Depends(require("archive:write"))) -> dict[str, Any]:
    for d in (body.since, body.until):
        if d is not None and not _DAY.match(d):
            raise error(422, "archive_bad_date")
    res = request.app.state.archive_worker.run_verify(body.since, body.until)
    state(request).audit.append(db, actor=ctx.user.username, action="archive.verify", target="archive", ip=ctx.ip,
                                outcome="success" if res["ok"] else "failure",
                                details={"since": body.since, "until": body.until,
                                         "checked": res["checked_files"], "problems": res["problem_count"]})
    return res


class RetentionBody(BaseModel):
    default: int
    days: dict[str, int] = {}


class RestoreBody(BaseModel):
    category: str
    since: str
    until: str
    days: int = 14


@router.get("/retention")
def get_retention(request: Request, ctx: Ctx = Depends(require("archive:read"))) -> dict[str, Any]:
    from ..archive_restore import DEFAULT_EXPIRY, MAX_DAYS, MAX_EXPIRY, MIN_DAYS
    w = request.app.state.archive_worker
    return {**w.retention.get(), "min": MIN_DAYS, "max": MAX_DAYS, "restore_days": DEFAULT_EXPIRY,
            "restore_max_days": MAX_EXPIRY}


@router.put("/retention")
def set_retention(body: RetentionBody, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("archive:write"))) -> dict[str, Any]:
    try:
        res = request.app.state.archive_worker.retention.set(body.default, body.days)
    except ValueError:
        raise error(422, "archive_bad_retention") from None
    state(request).audit.append(db, actor=ctx.user.username, action="archive.retention", target="archive",
                                ip=ctx.ip, outcome="success", details=res)
    return res


@router.get("/restores")
def list_restores(request: Request, ctx: Ctx = Depends(require("archive:read"))) -> list[dict[str, Any]]:
    return request.app.state.archive_worker.restorer.list()


@router.post("/restores")
def start_restore(body: RestoreBody, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("archive:write"))) -> dict[str, Any]:
    for d in (body.since, body.until):
        if not _DAY.match(d):
            raise error(422, "archive_bad_date")
    try:
        item = request.app.state.archive_worker.restorer.start(body.category, body.since, body.until, body.days,
                                                               ctx.user.username)
    except ValueError:
        raise error(422, "archive_bad_restore") from None
    except RuntimeError:
        raise error(409, "archive_restore_busy") from None
    state(request).audit.append(db, actor=ctx.user.username, action="archive.restore", target=body.category,
                                ip=ctx.ip, outcome="success",
                                details={"id": item["id"], "since": body.since, "until": body.until})
    return item


@router.delete("/restores/{rid}")
def delete_restore(rid: str, request: Request, db: DbSession = Depends(get_db),
                   ctx: Ctx = Depends(require("archive:write"))) -> dict[str, Any]:
    try:
        ok = request.app.state.archive_worker.restorer.delete(rid)
    except Exception:  # noqa: BLE001 – OpenSearch nicht erreichbar
        raise error(503, "opensearch_unavailable") from None
    if not ok:
        raise error(404, "archive_restore_not_found")
    state(request).audit.append(db, actor=ctx.user.username, action="archive.restore_delete", target=rid,
                                ip=ctx.ip, outcome="success", details={})
    return {"ok": True}
