"""Dashboard-Kennzahlen (Ampel je Bereich, Alarme, Top-Quellen)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from .. import dashboard
from ..deps import Ctx, require
from .logs import client_for

router = APIRouter(tags=["dashboard"], prefix="/api/dashboard")


@router.get("")
def get_dashboard(request: Request, ctx: Ctx = Depends(require("dashboard:read"))) -> dict:
    return dashboard.build(client_for(request), request.app.state.maintenance.state())
