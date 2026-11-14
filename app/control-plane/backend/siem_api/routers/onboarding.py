"""Anbindungs-Assistent: CA-Zertifikat und Konfigurationsausschnitte für TLS-Syslog."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response

from .. import onboarding as ob
from ..deps import Ctx, error, require, state

router = APIRouter(tags=["onboarding"], prefix="/api/onboarding")


def _host(request: Request) -> str:
    return (request.headers.get("host") or "siem").split(":")[0]


@router.get("/tls")
def tls(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> dict[str, Any]:
    try:
        info = ob.ca_info(state(request).settings.secrets_dir)
        snip = ob.snippets(_host(request), info["sha256"])
    except ob.OnboardingError as exc:
        raise error(409, exc.code) from None
    return {"host": _host(request), "port": 6514, "ca_sha256": info["sha256"], "ca_subject": info["subject"],
            "ca_expires": info["expires"], "snippets": snip}


@router.get("/ca.crt")
def ca_download(request: Request, ctx: Ctx = Depends(require("sources:read"))) -> Response:
    try:
        info = ob.ca_info(state(request).settings.secrets_dir)
    except ob.OnboardingError as exc:
        raise error(409, exc.code) from None
    return Response(info["pem"], media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="ca.crt"'})
