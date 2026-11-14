"""Vier-Augen-Freigaben und kontrollierte Aufdeckung pseudonymisierter Benutzernamen."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ..approvals import ACTIONS
from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchUnavailable
from .logs import client_for

router = APIRouter(tags=["approvals"], prefix="/api/approvals")


def gate(request: Request, db: DbSession, ctx: Ctx, action: str, params: dict[str, Any],
         approval_id: str | None) -> None:
    """Aktion nur mit gültiger Freigabe, falls das Vier-Augen-Prinzip eingeschaltet ist."""
    store = request.app.state.approvals
    if not store.enabled():
        return
    if approval_id and store.consume(approval_id, action, params, ctx.user.username):
        state(request).audit.append(db, actor=ctx.user.username, action="approval.used", target=approval_id,
                                    ip=ctx.ip, details={"action": action})
        return
    item = store.create(action, params, ctx.user.username)
    state(request).audit.append(db, actor=ctx.user.username, action="approval.requested", target=item["id"],
                                ip=ctx.ip, details={"action": action, "params": params})
    raise HTTPException(status_code=409, detail={"error": "approval_required", "approval_id": item["id"]})


class ConfigIn(BaseModel):
    enabled: bool


@router.get("/config")
def get_config(request: Request, ctx: Ctx = Depends(require("privacy:read"))) -> dict:
    return {"enabled": request.app.state.approvals.enabled(), "actions": ACTIONS}


@router.put("/config")
def put_config(body: ConfigIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("privacy:write"))) -> dict:
    request.app.state.approvals.set_enabled(body.enabled)
    state(request).audit.append(db, actor=ctx.user.username, action="approval.config", target="four-eyes",
                                ip=ctx.ip, details={"enabled": body.enabled})
    return {"enabled": body.enabled, "actions": ACTIONS}


@router.get("")
def list_items(request: Request, ctx: Ctx = Depends(require("privacy:read"))) -> list[dict]:
    return request.app.state.approvals.list()


def _decide(rid: str, ok: bool, request: Request, db: DbSession, ctx: Ctx) -> dict:
    try:
        item = request.app.state.approvals.decide(rid, ctx.user.username, ok, ctx.permissions)
    except KeyError:
        raise error(404, "approval_not_found") from None
    except ValueError:
        raise error(409, "approval_not_pending") from None
    except PermissionError as exc:
        raise error(403, "approval_self" if str(exc) == "self" else "forbidden") from None
    state(request).audit.append(db, actor=ctx.user.username, action="approval.approved" if ok else "approval.rejected",
                                target=rid, ip=ctx.ip,
                                details={"action": item["action"], "requester": item["requester"]})
    return item


@router.post("/{rid}/approve")
def approve(rid: str, request: Request, db: DbSession = Depends(get_db),
            ctx: Ctx = Depends(require("privacy:read"))) -> dict:
    return _decide(rid, True, request, db, ctx)


@router.post("/{rid}/reject")
def reject(rid: str, request: Request, db: DbSession = Depends(get_db),
           ctx: Ctx = Depends(require("privacy:read"))) -> dict:
    return _decide(rid, False, request, db, ctx)


class RevealIn(BaseModel):
    pseudonym: str = Field(pattern=r"^user_[0-9a-f]{8}$")
    reason: str = Field("", max_length=200)
    approval_id: str | None = None


@router.post("/reveal", tags=["privacy"])
def reveal(body: RevealIn, request: Request, db: DbSession = Depends(get_db),
           ctx: Ctx = Depends(require("privacy:read"))) -> dict:
    """Pseudonym → Klarname (Benutzernamen der letzten 90 Tage); jede Aufdeckung wird protokolliert."""
    st = request.app.state
    if not (st.approvals.enabled() or "privacy:approve" in ctx.permissions):
        raise error(403, "forbidden")  # ohne Vier-Augen-Prinzip nur Datenschutz-Freigeber
    gate(request, db, ctx, "privacy.reveal", {"pseudonym": body.pseudonym}, body.approval_id)
    q = {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-90d"}}},
         "aggs": {"u": {"terms": {"field": "user.name", "size": 10000}}}}
    try:
        resp = client_for(request).search("siem-*", q)
    except OpenSearchUnavailable:
        raise error(503, "opensearch_unavailable") from None
    names = [b["key"] for b in resp.get("aggregations", {}).get("u", {}).get("buckets", [])]
    found = next((n for n in names if st.privacy.pseudo(n) == body.pseudonym), None)
    state(request).audit.append(db, actor=ctx.user.username, action="privacy.reveal", target=body.pseudonym,
                                ip=ctx.ip, outcome="success" if found else "failure",
                                details={"reason": body.reason, "name": found})
    if not found:
        raise error(404, "pseudonym_unknown")
    return {"name": found}


