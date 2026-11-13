"""System-Informationen und Health-Endpunkt."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import __version__
from ..deps import Ctx, require

router = APIRouter(tags=["system"])


@router.get("/api/health")
def health() -> dict:
    """Ohne Anmeldung, ohne Detailinformationen (Spec 5.2a)."""
    return {"status": "ok"}


@router.get("/api/system/info")
def system_info(ctx: Ctx = Depends(require("system:read"))) -> dict:
    return {"version": __version__}
