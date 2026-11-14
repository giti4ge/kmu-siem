"""Wiederherstellung aus dem Archiv und Archiv-Retention (Spec 4.14a).

Die Wiederherstellung prüft die Dateien des Zeitraums gegen die Siegel und spielt die Ereignisse in tägliche Indizes
``siem-restore-<kategorie>-YYYY.MM.DD`` ein (gemeinsam mit Live-Daten durchsuchbar). Jede Wiederherstellung hat ein
Ablaufdatum (Standard 14 Tage); danach löscht die Control-Plane die Indizes. Die Archiv-Retention (Tage je Kategorie,
Standard 730) löscht versiegelte Dateien nach Ablauf und vermerkt jede Löschung in der Siegelkette.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .archive import Archive
from .opensearch import OpenSearchClient, OpenSearchUnavailable

DEFAULT_DAYS, MIN_DAYS, MAX_DAYS = 730, 30, 3650
DEFAULT_EXPIRY, MAX_EXPIRY = 14, 90
MAX_FILES = 200
BULK = 1000
_CAT = re.compile(r"^[a-z]+$")


class RetentionStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def get(self) -> dict[str, Any]:
        try:
            d = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            d = {}
        return {"default": int(d.get("default", DEFAULT_DAYS)), "days": dict(d.get("days", {}))}

    def set(self, default: int, days: dict[str, int]) -> dict[str, Any]:
        for v in [default, *days.values()]:
            if not MIN_DAYS <= v <= MAX_DAYS:
                raise ValueError("range")
        if any(not _CAT.match(c) for c in days):
            raise ValueError("category")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"default": default, "days": days}), "utf-8")
        os.replace(tmp, self.path)
        return self.get()


class Restorer:
    def __init__(self, archive: Archive, client: OpenSearchClient, state_path: Path,
                 report: Callable[[str, str, dict[str, Any]], None] | None = None) -> None:
        self.archive = archive
        self.client = client
        self.state_path = state_path
        self.report = report or (lambda *_a: None)
        self.lock = threading.Lock()
        items = self._load()
        if any(i["status"] == "running" for i in items):  # Neustart während einer Wiederherstellung
            self._save([{**i, "status": "failed", "error": "interrupted"} if i["status"] == "running" else i
                        for i in items])

    def _load(self) -> list[dict[str, Any]]:
        try:
            d = json.loads(self.state_path.read_text("utf-8"))
            return d if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def _save(self, items: list[dict[str, Any]]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items), "utf-8")
        os.replace(tmp, self.state_path)

    def list(self) -> list[dict[str, Any]]:
        with self.lock:
            return self._load()

    def _update(self, rid: str, **kv: Any) -> None:
        with self.lock:
            items = self._load()
            for it in items:
                if it["id"] == rid:
                    it.update(kv)
            self._save(items)

    def start(self, category: str, since: str, until: str, days: int, actor: str,
              background: bool = True) -> dict[str, Any]:
        if not _CAT.match(category) or category not in self.archive.categories():
            raise ValueError("category")
        if not 1 <= days <= MAX_EXPIRY or since > until:
            raise ValueError("range")
        now = datetime.now(UTC)
        item = {"id": uuid.uuid4().hex[:12], "category": category, "since": since, "until": until, "actor": actor,
                "created": now.isoformat(timespec="seconds"),
                "expires": (now + timedelta(days=days)).isoformat(timespec="seconds"),
                "status": "running", "events": 0, "indices": [], "error": None}
        with self.lock:
            items = self._load()
            if any(i["status"] == "running" for i in items):
                raise RuntimeError("busy")
            self._save([*items, item])
        if background:
            threading.Thread(target=self.run, args=(item["id"],), daemon=True, name="archive-restore").start()
        else:
            self.run(item["id"])
        return item

    def run(self, rid: str) -> None:
        item = next(i for i in self.list() if i["id"] == rid)
        try:
            files = self.archive.restore_events(item["category"], item["since"], item["until"])
            if len(files) > MAX_FILES:
                raise ValueError("too_many_files")
            total, indices = 0, set()
            for rel, lines in files:
                idx = f"siem-restore-{item['category']}-" + rel[:10].replace("/", ".")
                indices.add(idx)
                for i in range(0, len(lines), BULK):
                    chunk = lines[i:i + BULK]
                    head = json.dumps({"index": {"_index": idx}})
                    body = "".join(f"{head}\n{ln.rstrip()}\n" for ln in chunk)
                    resp = self.client.request("POST", "/_bulk", body.encode())
                    if resp and resp.get("errors"):
                        raise ValueError("bulk_errors")
                    total += len(chunk)
            self._update(rid, status="done", events=total, indices=sorted(indices))
            self.report("archive.restore", "success", {"id": rid, "events": total})
        except (ValueError, OSError, OpenSearchUnavailable) as exc:
            self._update(rid, status="failed", error=str(exc)[:200])
            self.report("archive.restore", "failure", {"id": rid, "error": str(exc)[:200]})

    def delete(self, rid: str) -> bool:
        item = next((i for i in self.list() if i["id"] == rid), None)
        if not item or item["status"] == "running":
            return False
        for idx in item["indices"]:
            self.client.request("DELETE", f"/{idx}")
        with self.lock:
            self._save([i for i in self._load() if i["id"] != rid])
        return True

    def expire(self) -> int:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        n = 0
        for it in self.list():
            if it["status"] != "running" and it["expires"] <= now:
                try:
                    n += self.delete(it["id"])
                except OpenSearchUnavailable:
                    pass
        return n
