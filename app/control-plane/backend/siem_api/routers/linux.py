"""Linux-Anbindung: Onboarding-Skript (rsyslog/TLS, optional auditd)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session as DbSession

from .. import linux_onboarding as lo
from ..deps import Ctx, error, get_db, require, state

router = APIRouter(tags=["linux"], prefix="/api/linux")


@router.get("/script")
def get_script(request: Request, server: str = Query(max_length=253), audit: bool = False,
               db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("sources:write"))) -> Response:
    st = state(request)
    try:
        script = lo.render_script(server, lo.read_ca(st.settings.secrets_dir), audit)
    except lo.LinuxOnboardingError as exc:
        raise error(400 if exc.code == "linux_invalid_server" else 503, exc.code) from exc
    digest = lo.script_sha256(script)
    st.audit.append(db, actor=ctx.user.username, action="linux.script", target=server, ip=ctx.ip,
                    details={"sha256": digest, "audit": audit})
    return Response(
        content=script, media_type="text/x-shellscript; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="siem-linux-onboarding.sh"',
                 "X-Script-SHA256": digest, "Cache-Control": "no-store"})
