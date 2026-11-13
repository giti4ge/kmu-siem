"""Audit-Log lesen und Integrität prüfen."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..deps import Ctx, get_db, require, state
from ..models import AuditEntry
from ..schemas import AuditOut, AuditVerifyOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(
    ctx: Ctx = Depends(require("audit:read")),
    db: DbSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    before_seq: int | None = Query(None, ge=1),
    actor: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
) -> list[AuditEntry]:
    stmt = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(limit)
    if before_seq is not None:
        stmt = stmt.where(AuditEntry.seq < before_seq)
    if actor:
        stmt = stmt.where(AuditEntry.actor == actor)
    if action:
        stmt = stmt.where(AuditEntry.action.startswith(action))
    return list(db.scalars(stmt).all())


@router.get("/verify", response_model=AuditVerifyOut)
def verify_audit(request: Request, ctx: Ctx = Depends(require("audit:read")),
                 db: DbSession = Depends(get_db)) -> AuditVerifyOut:
    st = state(request)
    result = st.audit.verify(db)
    st.audit.append(db, actor=ctx.user.username, action="audit.verify", ip=ctx.ip,
                    outcome="success" if result.ok else "failure",
                    details={"entries": result.entries, "reason": result.reason})
    return AuditVerifyOut(**result.__dict__)
