"""Einrichtungsassistent: Prüfliste mit Zustand und Direktlinks (Spec 5.1, Feature-Katalog)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..deps import Ctx, get_db, require
from ..models import Device

router = APIRouter(tags=["setup"], prefix="/api/setup")


def checks(request: Request, db: DbSession) -> list[dict[str, Any]]:
    app = request.app.state
    notify = app.notify_store.config()
    forti = app.forti_store.config()
    maint = app.maintenance.state()
    devices = db.scalar(select(func.count()).select_from(Device)) or 0
    ai = app.ai_store.config()
    ar = app.ar_store.config()
    backup = maint.get("db_backup") or {}
    return [
        {"id": "notify", "ok": bool(notify["email_enabled"] or notify["teams_enabled"]), "optional": False,
         "link": "/system/notifications"},
        {"id": "devices", "ok": devices > 0, "optional": False, "link": "/sources/devices", "count": devices},
        {"id": "fortigate", "ok": bool(forti["enabled"]), "optional": True, "link": "/sources/fortigate"},
        {"id": "windows", "ok": None, "optional": True, "link": "/sources/windows"},
        {"id": "retention", "ok": None, "optional": True, "link": "/system/retention"},
        {"id": "backup", "ok": bool(backup.get("ok")), "optional": False, "link": "/system/maintenance"},
        {"id": "ai", "ok": bool(ai["enabled"]), "optional": True, "link": "/forensics"},
        {"id": "ar", "ok": bool(ar["enabled"]), "optional": True, "link": "/active-response"},
    ]


@router.get("")
def get_setup(request: Request, db: DbSession = Depends(get_db), ctx: Ctx = Depends(require("dashboard:read"))) -> dict:
    items = checks(request, db)
    return {"items": items, "open_required": sum(1 for i in items if not i["optional"] and not i["ok"])}
