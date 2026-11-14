"""Forensik-Export: signiertes Beweispaket erzeugen und prüfen."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import forensic_export as fx
from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchUnavailable
from .approvals import gate
from .logs import client_for

router = APIRouter(tags=["forensics"], prefix="/api/forensics")


class ExportIn(BaseModel):
    field: Literal["user.name", "host.name", "source.ip", "destination.ip", "siem.case.id"]
    value: str = Field(min_length=1, max_length=200)
    hours: int = Field(24, ge=1, le=720)
    approval_id: str | None = None


@router.post("/export")
def export(body: ExportIn, request: Request, db: DbSession = Depends(get_db),
           ctx: Ctx = Depends(require("logs:read"))) -> Response:
    gate(request, db, ctx, "forensics.export", {"field": body.field, "value": body.value, "hours": body.hours},
         body.approval_id)
    q = {"size": fx.MAX_EVENTS, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": f"now-{body.hours}h"}}}, {"term": {body.field: body.value}}],
        "must_not": [{"term": {"siem.category": "unparsed"}}]}}}
    try:
        resp = client_for(request).search("siem-*", q)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    events = [{"_index": h.get("_index"), "_id": h.get("_id"), "_source": h.get("_source", {})}
              for h in resp.get("hits", {}).get("hits", [])]
    meta = {"field": body.field, "value": body.value, "hours": body.hours, "exported_by": ctx.user.username}
    data, digest = fx.build(events, meta, state(request).keys.audit_key)
    state(request).audit.append(db, actor=ctx.user.username, action="forensics.export", target=f"{body.field}={body.value}"[:100],
                                ip=ctx.ip, details={"events": len(events), "sha256": digest, "hours": body.hours})
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": 'attachment; filename="forensik-paket.zip"', "X-Package-SHA256": digest})


@router.post("/verify")
async def verify(request: Request, ctx: Ctx = Depends(require("logs:read"))) -> dict:
    body = await request.body()
    if not body or len(body) > fx.MAX_PACKAGE:
        raise error(400, "invalid_request")
    return fx.verify(body, state(request).keys.audit_key)
