"""Datenschutzmodus (Spec 4.13): Benutzernamen für Analyst/Auditor/Management als Pseudonym anzeigen.

Gespeichert wird im Klartext; maskiert wird nur die Ausgabe der API. Administratoren (``system:write``) und
Datenschutz-Freigeber (``privacy:approve``) sehen Klartext – jede Änderung der Einstellung steht im Audit-Log.
Die Aufdeckung durch ein Vier-Augen-Verfahren ist über den optionalen Schalter für eine spätere Version vorgesehen.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from . import sophos


class Privacy:
    def __init__(self, secrets_dir: Path, master_key: bytes) -> None:
        self.path = secrets_dir / "privacy.json"
        self.key = hmac.new(master_key, b"privacy.pseudonym", hashlib.sha256).digest()

    def enabled(self) -> bool:
        return bool(sophos._read(self.path).get("enabled"))

    def set_enabled(self, value: bool) -> None:
        sophos._write(self.path, {"enabled": bool(value)})

    def masked_for(self, permissions: set[str]) -> bool:
        return self.enabled() and "system:write" not in permissions and "privacy:approve" not in permissions

    def pseudo(self, value: Any) -> Any:
        if not value:
            return value
        return "user_" + hmac.new(self.key, str(value).lower().encode(), hashlib.sha256).hexdigest()[:8]

    # ---- Anwendung auf Ausgaben ----
    def alerts(self, rows: list[dict[str, Any]]) -> None:
        for r in rows:
            if r.get("group_by") == "user.name" and r.get("group"):
                g = str(r["group"])
                r["summary"] = str(r.get("summary", "")).replace(g, self.pseudo(g))
                r["group"] = self.pseudo(g)
            r["sample"] = ""  # Rohzeilen können Namen enthalten

    def changes(self, rows: list[dict[str, Any]]) -> None:
        for r in rows:
            for k in ("actor", "member"):
                r[k] = self.pseudo(r.get(k))
            if r.get("object_class") == "user":
                r["object"] = self.pseudo(r.get("object"))

    def counts(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{**r, "key": self.pseudo(r["key"])} for r in rows]
