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
