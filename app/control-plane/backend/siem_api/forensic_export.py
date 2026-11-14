"""Forensik-Export (Spec 4.15, ADR-23): signiertes Paket mit Hashliste und Zugriffsnachweis.

Paket (ZIP): ``events.jsonl`` (Rohdaten je Zeile mit Index und ID), ``manifest.json`` (Erzeuger, Filter, Zeitpunkt,
SHA-256 je Datei) und ``manifest.sig`` (HMAC-SHA256 über das Manifest mit dem Audit-Schlüssel der Appliance).
Der SHA-256 des Gesamtpakets wird zusätzlich in die Audit-Kette geschrieben (Zugriffsnachweis). Ein externer
RFC-3161-Zeitstempel ist vorgesehen, aber noch nicht angebunden; bis dahin belegt die Audit-Kette den Zeitpunkt.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any

MAX_EVENTS = 10000
MAX_PACKAGE = 100 * 1024 * 1024


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def build(events: list[dict[str, Any]], meta: dict[str, Any], key: bytes, now: datetime | None = None) -> tuple[bytes, str]:
    """Paket erzeugen; Rückgabe (ZIP-Bytes, SHA-256 des Pakets)."""
    lines = b"".join(_canonical(e) + b"\n" for e in events)
    manifest = {
        "format": "kmu-siem-forensic-package/1", "created": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
        "events": len(events), "filter": meta,
        "files": {"events.jsonl": {"sha256": hashlib.sha256(lines).hexdigest(), "bytes": len(lines)}},
        "hinweis": "Integritätsnachweis der Appliance; Zeitstempel nach RFC 3161 ist optional und nicht enthalten.",
    }
    m = json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2).encode()
    sig = hmac.new(key, m, hashlib.sha256).hexdigest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("events.jsonl", lines)
        z.writestr("manifest.json", m)
        z.writestr("manifest.sig", sig + "\n")
    data = buf.getvalue()
    return data, hashlib.sha256(data).hexdigest()


def verify(package: bytes, key: bytes) -> dict[str, Any]:
    """Prüft Signatur des Manifests und die Hashes der Dateien."""
    try:
        with zipfile.ZipFile(io.BytesIO(package)) as z:
            names = set(z.namelist())
            if not {"manifest.json", "manifest.sig", "events.jsonl"} <= names or len(names) != 3:
                return {"ok": False, "reason": "Paketaufbau ungültig"}
            m, sig, ev = z.read("manifest.json"), z.read("manifest.sig").decode().strip(), z.read("events.jsonl")
    except (zipfile.BadZipFile, OSError):
        return {"ok": False, "reason": "kein gültiges Paket"}
    if not hmac.compare_digest(sig, hmac.new(key, m, hashlib.sha256).hexdigest()):
        return {"ok": False, "reason": "Signatur ungültig (Manifest verändert oder fremdes Gerät)"}
    manifest = json.loads(m)
    info = manifest.get("files", {}).get("events.jsonl", {})
    if info.get("sha256") != hashlib.sha256(ev).hexdigest():
        return {"ok": False, "reason": "Hash von events.jsonl stimmt nicht (Daten verändert)"}
    return {"ok": True, "created": manifest.get("created"), "events": manifest.get("events"), "filter": manifest.get("filter")}
