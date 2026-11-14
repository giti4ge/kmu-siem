"""Reports: Zusammenfassung und CSV-Export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session as DbSession

from .. import reports
from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchUnavailable
from .alerts import _row
from .logs import client_for

router = APIRouter(tags=["reports"], prefix="/api/reports")


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365), ctx: Ctx = Depends(require("reports:read"))) -> dict:
    try:
        return reports.summary(client_for(request), days)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc


@router.get("/alerts.csv")
def alerts_csv(request: Request, days: int = Query(30, ge=1, le=365), db: DbSession = Depends(get_db),
               ctx: Ctx = Depends(require("reports:read"))) -> Response:
    try:
        resp = client_for(request).search("siem-alerts-*", {"size": 5000, "sort": [{"@timestamp": "desc"}],
                                                            "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}}})
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    rows = [_row(h) for h in resp.get("hits", {}).get("hits", [])]
    state(request).audit.append(db, actor=ctx.user.username, action="report.export", target="alerts.csv", ip=ctx.ip,
                                details={"rows": len(rows), "days": days})
    return Response(reports.alerts_csv(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="alarme.csv"'})
