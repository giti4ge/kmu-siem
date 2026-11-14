"""Vier-Augen-Prinzip (Spec 4.13), optional und ab Werk aus.

Ist es eingeschaltet, brauchen sensible Aktionen die Freigabe einer zweiten Person mit der Berechtigung
``<modul>:approve`` (nicht die antragstellende Person). Ablauf: Die Aktion ohne Freigabe liefert 409
``approval_required`` und legt einen Antrag an; die Freigabe erfolgt unter Datenschutz → Freigaben; danach wiederholt
die antragstellende Person die Aktion mit ``approval_id``. Die Freigabe gilt einmal, nur für exakt diese Parameter und
läuft nach 24 h ab. Antrag, Freigabe und Ablehnung stehen im Audit-Log.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ACTIONS = {
    "archive.restore": "archive:approve",
    "forensics.export": "logs:approve",
    "alert.close": "alerts:approve",
    "privacy.reveal": "privacy:approve",
}
TTL = timedelta(hours=24)


def _digest(params: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        try:
            d = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            d = {}
        return {"enabled": bool(d.get("enabled", False)), "items": list(d.get("items", []))}

    def _save(self, d: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d), "utf-8")
        os.replace(tmp, self.path)

    def enabled(self) -> bool:
        return self._load()["enabled"]

    def set_enabled(self, value: bool) -> None:
        with self.lock:
            d = self._load()
            d["enabled"] = bool(value)
            self._save(d)

    def list(self, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or datetime.now(UTC)
        with self.lock:
            d = self._load()
            cut = (now - timedelta(days=30)).isoformat(timespec="seconds")
            keep = [i for i in d["items"] if i["created"] >= cut]
            for i in keep:
                if i["status"] == "pending" and i["expires"] <= now.isoformat(timespec="seconds"):
                    i["status"] = "expired"
            d["items"] = keep
            self._save(d)
            return [{k: v for k, v in i.items() if k != "digest"} for i in keep]

    def create(self, action: str, params: dict[str, Any], requester: str, reason: str = "",
               now: datetime | None = None) -> dict[str, Any]:
        if action not in ACTIONS:
            raise ValueError(action)
        now = now or datetime.now(UTC)
        dig = _digest(params)
        with self.lock:
            d = self._load()
            for i in d["items"]:  # vorhandenen offenen Antrag wiederverwenden
                if (i["action"], i["digest"], i["requester"], i["status"]) == (action, dig, requester, "pending") \
                        and i["expires"] > now.isoformat(timespec="seconds"):
                    return i
            item = {"id": uuid.uuid4().hex[:12], "action": action, "params": params, "digest": dig,
                    "requester": requester, "reason": reason[:200], "status": "pending",
                    "created": now.isoformat(timespec="seconds"),
                    "expires": (now + TTL).isoformat(timespec="seconds"), "decided_by": None}
            d["items"].append(item)
            self._save(d)
            return item

    def decide(self, rid: str, approver: str, approve: bool, permissions: set[str],
               now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        with self.lock:
            d = self._load()
            item = next((i for i in d["items"] if i["id"] == rid), None)
            if item is None:
                raise KeyError(rid)
            if item["status"] != "pending" or item["expires"] <= now.isoformat(timespec="seconds"):
                raise ValueError("not_pending")
            if approver == item["requester"]:
                raise PermissionError("self")
            if ACTIONS[item["action"]] not in permissions:
                raise PermissionError("permission")
            item["status"] = "approved" if approve else "rejected"
            item["decided_by"] = approver
            item["decided"] = now.isoformat(timespec="seconds")
            self._save(d)
            return item

    def consume(self, rid: str, action: str, params: dict[str, Any], requester: str,
                now: datetime | None = None) -> bool:
        """Freigabe einlösen (einmalig, nur für gleiche Aktion, Parameter und antragstellende Person)."""
        now = now or datetime.now(UTC)
        with self.lock:
            d = self._load()
            for i in d["items"]:
                if i["id"] == rid and i["status"] == "approved" and i["action"] == action \
                        and i["requester"] == requester and i["digest"] == _digest(params) \
                        and i["expires"] > now.isoformat(timespec="seconds"):
                    i["status"] = "used"
                    self._save(d)
                    return True
        return False
