"""Fälle: anlegen, Notizen und Ereignisse als Beweisstücke hinzufügen, schließen (Write-once-Fallarchiv)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import cases as cs
from ..deps import Ctx, error, get_db, require, state
from ..models import Case
from ..opensearch import OpenSearchUnavailable
from .logs import client_for

router = APIRouter(tags=["cases"], prefix="/api/cases")


def _wrap(fn):
    try:
        return fn()
    except cs.CaseError as exc:
        code = 404 if exc.code in ("case_not_found",) else 409
        raise error(code, exc.code) from None


class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=4000)
    retention_months: int = Field(cs.DEFAULT_RETENTION_MONTHS, ge=1, le=120)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class EventIn(BaseModel):
    index: str = Field(pattern=r"^siem-[a-z-]+-\d{4}\.\d{2}\.\d{2}$")
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{6,64}$")


def _masked(request: Request, ctx: Ctx) -> bool:
    return request.app.state.privacy.masked_for(ctx.permissions)


@router.get("")
def list_cases(request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("logs:read"))) -> list[dict[str, Any]]:
    return [cs.view(c) for c in db.scalars(select(Case).order_by(Case.id.desc()).limit(500))]


@router.post("")
def create_case(body: CaseIn, request: Request, db: DbSession = Depends(get_db),
                ctx: Ctx = Depends(require("alerts:write"))) -> dict[str, Any]:
    c = cs.create(db, body.title, body.description, ctx.user.username, body.retention_months)
    state(request).audit.append(db, actor=ctx.user.username, action="case.create", target=str(c.id), ip=ctx.ip,
                                details={"title": c.title})
    return cs.view(c, [])


@router.get("/{cid}")
def get_case(cid: int, request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("logs:read"))) -> dict[str, Any]:
    c = _wrap(lambda: cs.get(db, cid))
    return cs.view(c, cs.items(db, cid), with_events=not _masked(request, ctx))


@router.post("/{cid}/notes")
def add_note(cid: int, body: NoteIn, request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("alerts:write"))) -> dict[str, Any]:
    c = _wrap(lambda: cs.get(db, cid))
    it = _wrap(lambda: cs.add_item(db, c, "note", {"text": body.text}, ctx.user.username))
    state(request).audit.append(db, actor=ctx.user.username, action="case.note", target=str(cid), ip=ctx.ip,
                                details={"sha256": it.sha256})
    return {"id": it.id, "sha256": it.sha256}


@router.post("/{cid}/events")
def add_event(cid: int, body: EventIn, request: Request, db: DbSession = Depends(get_db),
              ctx: Ctx = Depends(require("alerts:write"))) -> dict[str, Any]:
    c = _wrap(lambda: cs.get(db, cid))
    try:
        doc = client_for(request).request("GET", f"/{body.index}/_doc/{body.id}")
    except OpenSearchUnavailable:
        raise error(503, "opensearch_unavailable") from None
    if not doc or "_source" not in doc:
        raise error(404, "event_not_found")
    it = _wrap(lambda: cs.add_item(db, c, "event",
                                   {"_index": body.index, "_id": body.id, "_source": doc["_source"]},
                                   ctx.user.username))
    state(request).audit.append(db, actor=ctx.user.username, action="case.event", target=str(cid), ip=ctx.ip,
                                details={"index": body.index, "id": body.id, "sha256": it.sha256})
    return {"id": it.id, "sha256": it.sha256}


@router.post("/{cid}/close")
def close_case(cid: int, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("alerts:write"))) -> dict[str, Any]:
    c = _wrap(lambda: cs.get(db, cid))
    st = state(request)
    worker = request.app.state.archive_worker
    res = _wrap(lambda: cs.close(db, c, ctx.user.username, st.settings.archive_dir, worker.archive.key,
                                 st.keys.audit_key))
    st.audit.append(db, actor=ctx.user.username, action="case.close", target=str(cid), ip=ctx.ip, details=res)
    return res


@router.get("/{cid}/package")
def download(cid: int, request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("logs:read"))) -> Response:
    c = _wrap(lambda: cs.get(db, cid))
    data = _wrap(lambda: cs.package(c, state(request).settings.archive_dir))
    state(request).audit.append(db, actor=ctx.user.username, action="case.package", target=str(cid), ip=ctx.ip,
                                details={"sha256": c.package_sha256})
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="fall-{cid}.zip"', "X-Package-SHA256": c.package_sha256 or ""})
