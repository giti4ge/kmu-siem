"""Alarme (Liste, Bestätigen/Schließen) und Regeln (Übersicht, an/aus, Schweregrad, Schwellwert)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import alerts as al
from .. import mitre
from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchUnavailable
from .approvals import gate
from .logs import client_for

router = APIRouter(tags=["alerts"], prefix="/api/alerts")


def _row(hit: dict[str, Any]) -> dict[str, Any]:
    s = hit.get("_source", {})
    a = s.get("alert", {})
    return {"id": a.get("id"), "index": hit.get("_index"), "time": s.get("@timestamp"), "rule_id": s.get("rule", {}).get("id"),
            "rule": s.get("rule", {}).get("name"), "severity": a.get("severity"), "status": a.get("status"),
            "group": a.get("group"), "group_by": a.get("group_by"), "count": a.get("count"),
            "last_seen": a.get("last_seen"), "summary": a.get("summary"), "sample": a.get("sample"),
            "mitre": a.get("mitre", []), "description": a.get("description"), "ack_by": a.get("ack_by")}


@router.get("")
def list_alerts(request: Request, hours: int = Query(168, ge=1, le=2160), status_: str | None = Query(None, alias="status"),
                severity: str | None = Query(None), ctx: Ctx = Depends(require("alerts:read"))) -> dict:
    flt: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if status_ in al.STATUSES:
        flt.append({"term": {"alert.status": status_}})
    if severity in al.SEVERITIES:
        flt.append({"term": {"alert.severity": severity}})
    body = {"size": 200, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": flt}},
            "aggs": {"sev": {"terms": {"field": "alert.severity", "size": 10}}}}
    try:
        resp = client_for(request).search("siem-alerts-*", body)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    rows = [_row(h) for h in resp.get("hits", {}).get("hits", [])]
    rows.sort(key=lambda r: (r["status"] != "open", al.SEVERITIES.index(r["severity"]) * -1 if r["severity"] in al.SEVERITIES else 0))
    if request.app.state.privacy.masked_for(ctx.permissions):
        request.app.state.privacy.alerts(rows)
    return {"alerts": rows, "engine": request.app.state.alert_engine.last}


class StatusIn(BaseModel):
    status: Literal["open", "acknowledged", "closed"]
    index: str = Field(pattern=r"^siem-alerts-\d{4}\.\d{2}\.\d{2}$")
    approval_id: str | None = None


@router.post("/{alert_id}/status")
def set_status(alert_id: str, body: StatusIn, request: Request, db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("alerts:write"))) -> dict:
    if not (len(alert_id) == 32 and all(c in "0123456789abcdef" for c in alert_id)):
        raise error(400, "invalid_request")
    if body.status == "closed" and request.app.state.approvals.enabled():
        try:
            doc = client_for(request).request("GET", f"/{body.index}/_doc/{alert_id}") or {}
        except OpenSearchUnavailable as exc:
            raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
        if (doc.get("_source", {}).get("alert", {}).get("severity") or doc.get("_source", {}).get("severity")) == "critical":
            gate(request, db, ctx, "alert.close", {"alert": alert_id}, body.approval_id)
    try:
        r = client_for(request).request("POST", f"/{body.index}/_update/{alert_id}?refresh=true",
                                        {"doc": {"alert": {"status": body.status, "ack_by": ctx.user.username}}})
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    if r is None:
        raise error(404, "alert_not_found")
    state(request).audit.append(db, actor=ctx.user.username, action="alert.status", target=alert_id, ip=ctx.ip,
                                details={"status": body.status})
    return {"ok": True}


class RuleIn(BaseModel):
    enabled: bool | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    threshold: int | None = Field(None, ge=1, le=100000)


@router.get("/rules")
def list_rules(request: Request, ctx: Ctx = Depends(require("rules:read"))) -> dict:
    return {"rules": [al.rule_view(r) for r in request.app.state.alert_store.rules()]}


@router.get("/mitre")
def mitre_matrix(request: Request, ctx: Ctx = Depends(require("rules:read"))) -> dict:
    return mitre.matrix(request.app.state.alert_store.rules())


@router.put("/rules/{rule_id}")
def put_rule(rule_id: str, body: RuleIn, request: Request, db: DbSession = Depends(get_db),
             ctx: Ctx = Depends(require("rules:write"))) -> dict:
    if rule_id not in {r.id for r in al.BUILTIN_RULES}:
        raise error(404, "rule_not_found")
    changes = body.model_dump(exclude_none=True)
    if changes:
        request.app.state.alert_store.update(rule_id, changes)
        state(request).audit.append(db, actor=ctx.user.username, action="rule.update", target=rule_id, ip=ctx.ip,
                                    details=changes)
    return {"rules": [al.rule_view(r) for r in request.app.state.alert_store.rules()]}
