"""System-Informationen, Health-Endpunkt und System-Protokoll."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session as DbSession

from .. import __version__, diagnostics, hostd
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["system"])

# Muss den Quellen in siem-hostd (LOG_SOURCES) entsprechen
LogSource = Literal[
    "install", "hostd-audit", "siem-hostd", "docker", "nftables", "ssh", "chrony", "unattended-upgrades",
    "opensearch", "vector", "proxy", "api", "dashboards",
]


@router.get("/api/health")
def health() -> dict:
    """Ohne Anmeldung, ohne Detailinformationen (Spec 5.2a)."""
    return {"status": "ok"}


@router.get("/api/system/info")
def system_info(ctx: Ctx = Depends(require("system:read"))) -> dict:
    return {"version": __version__}


@router.get("/api/system/diagnostics")
def diagnostics_package(request: Request, db: DbSession = Depends(get_db), pseudonymize: bool = True,
                        ctx: Ctx = Depends(require("system:read"))) -> dict:
    """Diagnosepaket für den Dienstleister (ohne Geheimnisse/Ereignisinhalte, Namen/IPs optional pseudonymisiert)."""
    st = state(request)
    pkg = diagnostics.build(st.settings, f"{ctx.user.username}@web", request.app.state.maintenance.state(), pseudonymize)  # noqa: E501
    st.audit.append(db, actor=ctx.user.username, action="system.diagnostics", target="package", ip=ctx.ip,
                    details={"pseudonymized": pseudonymize})
    return pkg


@router.get("/api/system/logs")
def system_logs(
    request: Request,
    ctx: Ctx = Depends(require("system:read")),
    source: LogSource = Query("install"),
    lines: int = Query(500, ge=1, le=2000),
    query: str = Query("", max_length=100),
) -> dict:
    """System-Protokoll über siem-hostd (nur lesen, feste Quellen)."""
    try:
        return hostd.call(state(request).settings.hostd_socket, "system.logs",
                          {"source": source, "lines": lines, "query": query}, actor=f"{ctx.user.username}@web")
    except hostd.HostdUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "hostd_unavailable") from exc
    except hostd.HostdRejected as exc:
        raise error(status.HTTP_400_BAD_REQUEST, "invalid_request") from exc
