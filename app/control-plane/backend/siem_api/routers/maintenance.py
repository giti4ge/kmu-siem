"""Wartung: Zustand der Jobs (Plattenwächter, Sicherung, Snapshots) und manueller Start."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DbSession

from .. import maintenance as mt
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["maintenance"], prefix="/api/maintenance")


def _sched(request: Request) -> mt.Scheduler:
    return request.app.state.maintenance


@router.get("")
def get_status(request: Request, ctx: Ctx = Depends(require("system:read"))) -> dict[str, Any]:
    sched = _sched(request)
    st = sched.state()
    return {"jobs": {j: st.get(j) for j in mt.JOBS},
            "window": {"start": mt.WINDOW_START, "end": mt.WINDOW_END},
            "thresholds": {"warn": mt.WARN_PERCENT, "emergency": mt.EMERGENCY_PERCENT, "target": mt.TARGET_PERCENT},
            "keep": {"db_backups": mt.KEEP_DB_BACKUPS, "snapshots": mt.KEEP_SNAPSHOTS}}


@router.post("/run/{job}")
def run_job(job: str, request: Request, db: DbSession = Depends(get_db),
            ctx: Ctx = Depends(require("system:write"))) -> dict[str, Any]:
    if job not in mt.JOBS:
        raise error(404, "maintenance_unknown_job")
    result = _sched(request).run_job(job)
    state(request).audit.append(db, actor=ctx.user.username, action="maintenance.run", target=job, ip=ctx.ip,
                                outcome="success" if result["ok"] else "failure", details={})
    return result
