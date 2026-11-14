"""Konfigurations-Snapshots von Geräten (derzeit FortiGate über die REST-API; Spec 4.16).

Täglich (und auf Knopfdruck) wird die Konfiguration gesichert, Geheimnisse (``ENC …``) werden durch einen
Hash-Platzhalter ersetzt (Änderungen bleiben sichtbar, Werte nicht). Nur geänderte Stände werden abgelegt;
Vergleich zweier Stände als Diff. Aufbewahrt werden die letzten 60 Stände.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

KEEP = 60
MAX_DIFF_LINES = 3000
_NAME = re.compile(r"^\d{8}-\d{6}\.conf$")
_ENC = re.compile(r"\bENC\s+(\S+)")
_SECRET_QUOTED = re.compile(
    r'^([ \t]*set[ \t]+\S*(?:password|passwd|psksecret|secret|token|community)\S*[ \t]+)"[^"\n]*"[ \t]*$',
    re.I | re.M)


class SnapshotError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def redact(text: str) -> str:
    def enc(m: re.Match[str]) -> str:
        return "ENC [sha256:" + hashlib.sha256(m.group(1).encode()).hexdigest()[:8] + "]"

    def plain(m: re.Match[str]) -> str:
        return m.group(1) + '"[redacted]"'
    return _SECRET_QUOTED.sub(plain, _ENC.sub(enc, text))


class Store:
    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def list(self) -> list[dict[str, Any]]:
        try:
            names = sorted((p for p in self.dir.iterdir() if _NAME.match(p.name)), reverse=True)
        except OSError:
            return []
        return [{"name": p.name, "bytes": p.stat().st_size,
                 "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in names]

    def read(self, name: str) -> str:
        if not _NAME.match(name):
            raise SnapshotError("snapshot_not_found")
        try:
            return (self.dir / name).read_bytes().decode("utf-8")
        except OSError:
            raise SnapshotError("snapshot_not_found") from None

    def take(self, fetch: Callable[[], str], now: datetime | None = None) -> dict[str, Any]:
        text = redact(fetch())
        if not text.strip():
            raise SnapshotError("snapshot_empty")
        digest = hashlib.sha256(text.encode()).hexdigest()
        existing = self.list()
        if existing and existing[0]["sha256"] == digest:
            return {"changed": False, "name": existing[0]["name"], "sha256": digest}
        now = now or datetime.now(UTC)
        name = now.strftime("%Y%m%d-%H%M%S") + ".conf"
        self.dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = self.dir / (name + ".tmp")
        tmp.write_bytes(text.encode())  # Bytes: gleiche Hashes unter jedem Betriebssystem
        os.chmod(tmp, 0o640)
        os.replace(tmp, self.dir / name)
        for old in self.list()[KEEP:]:
            (self.dir / old["name"]).unlink(missing_ok=True)
        added = removed = 0
        if existing:
            for ln in difflib.unified_diff(self.read(existing[0]["name"]).splitlines(), text.splitlines(), n=0,
                                           lineterm=""):
                if ln.startswith("+") and not ln.startswith("+++"):
                    added += 1
                elif ln.startswith("-") and not ln.startswith("---"):
                    removed += 1
        return {"changed": True, "name": name, "sha256": digest, "first": not existing, "added": added,
                "removed": removed}

    def diff(self, a: str, b: str) -> list[str]:
        lines = list(difflib.unified_diff(self.read(a).splitlines(), self.read(b).splitlines(), fromfile=a,
                                          tofile=b, n=2, lineterm=""))
        return lines[:MAX_DIFF_LINES]
