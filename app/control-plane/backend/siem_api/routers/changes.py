"""Change-Timeline: „Wer hat wann was geändert (alt → neu)“ aus den siem.change.*-Ereignissen."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status

from ..deps import Ctx, error, require
from ..opensearch import OpenSearchUnavailable
from .logs import client_for

router = APIRouter(tags=["changes"], prefix="/api/changes")

PAIR_SECONDS = 5


def build_query(hours: int, q: str | None, privileged: bool, limit: int) -> dict[str, Any]:
    must: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                                  {"exists": {"field": "siem.change.operation"}}]
    if privileged:
        must.append({"term": {"siem.change.privileged": True}})
    if q:
        must.append({"simple_query_string": {
            "query": q, "default_operator": "and",
            "fields": ["siem.change.actor", "siem.change.object", "siem.change.attribute", "siem.change.member",
                       "host.name", "message"]}})
    return {"size": limit, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": must}}}


def _ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _row(src: dict[str, Any]) -> dict[str, Any]:
    ch = src.get("siem", {}).get("change", {})
    return {
        "time": src.get("@timestamp"), "host": src.get("host", {}).get("name"),
        "action": src.get("event", {}).get("action"), "operation": ch.get("operation"),
        "actor": ch.get("actor") or src.get("user", {}).get("name"), "object": ch.get("object"),
        "object_class": ch.get("object_class"), "attribute": ch.get("attribute"), "member": ch.get("member"),
        "old_value": None, "new_value": ch.get("new_value"),
        "privileged": bool(ch.get("privileged")), "gpo": bool(ch.get("gpo")),
    }


def pair_changes(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """AD-Attributänderungen bestehen aus „Wert gelöscht“ + „Wert hinzugefügt“ (5136); beide werden zu alt → neu."""
    rows = [_row(h.get("_source", {})) for h in hits if h.get("_source", {}).get("@timestamp")]
    rows.sort(key=lambda r: _ts(r["time"]))  # chronologisch
    out: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []  # noch nicht zugeordnete Löschungen
    for r in rows:
        key = (r["actor"], r["object"], r["attribute"])
        if r["operation"] == "value-deleted" and r["attribute"]:
            pending.append(r)
            continue
        if r["operation"] == "value-added" and r["attribute"]:
            for p in pending:
                same = (p["actor"], p["object"], p["attribute"]) == key
                if same and 0 <= _ts(r["time"]) - _ts(p["time"]) <= PAIR_SECONDS:
                    r["old_value"] = p["new_value"]
                    pending.remove(p)
                    break
        out.append(r)
    out.extend(pending)  # reine Löschungen bleiben als Änderung sichtbar (neu = leer)
    for p in pending:
        p["old_value"], p["new_value"] = p["new_value"], None
    out.sort(key=lambda r: _ts(r["time"]), reverse=True)
    return out


@router.get("")
def timeline(request: Request, hours: int = Query(24, ge=1, le=720), q: str | None = Query(None, max_length=200),
             privileged: bool = False, limit: int = Query(500, ge=1, le=2000),
             ctx: Ctx = Depends(require("changes:read"))) -> dict:
    try:
        resp = client_for(request).search("siem-windows-*", build_query(hours, q, privileged, limit))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    hits = resp.get("hits", {}).get("hits", [])
    rows = pair_changes(hits)
    if request.app.state.privacy.masked_for(ctx.permissions):
        request.app.state.privacy.changes(rows)
    return {"hours": hours, "changes": rows, "truncated": len(hits) >= limit}
