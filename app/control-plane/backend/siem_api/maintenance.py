"""Wartungsjobs (Spec 4.5/4.16): Plattenwächter, Config-DB-Sicherung, Integritätsprüfung, OpenSearch-Snapshots.

Ein Hintergrundthread führt die Jobs aus: der Plattenwächter alle 5 min, die übrigen im nächtlichen Wartungsfenster
(Standard 02:00–04:00, je Job einmal pro Tag bzw. Woche). Ergebnis und letzter Lauf stehen in ``maintenance.json``
(Anzeige im Web-UI); Fehler und jede Notlöschung gehen als Ereignis in das Audit-Log. E-Mail/Teams-Alarme folgen mit
der Alert-Engine (Phase 5), bis dahin zeigt das Dashboard den Zustand.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .opensearch import OpenSearchClient, OpenSearchUnavailable

GUARD_INTERVAL = 300
WARN_PERCENT = 75.0
EMERGENCY_PERCENT = 85.0
TARGET_PERCENT = 80.0  # Notbereinigung löscht, bis diese Belegung unterschritten ist
MAX_DELETIONS_PER_CYCLE = 20
KEEP_DB_BACKUPS = 14
KEEP_SNAPSHOTS = 7
WINDOW_START, WINDOW_END = 2, 4
REPO = "siem-local"
JOBS = ("guard", "db_backup", "db_integrity", "snapshot")

# Reihenfolge der Notbereinigung: zuerst weniger wichtige Kategorien; audit und alerts zuletzt
DELETE_ORDER = ("unparsed", "asset", "infra", "network", "av", "edr", "linux", "firewall", "windows", "alerts", "audit")
_INDEX = re.compile(r"^siem-([a-z]+)-(\d{4}\.\d{2}\.\d{2})$")
_BACKUP = re.compile(r"^siem-(\d{8}-\d{6})\.db$")
_SNAP = re.compile(r"^daily-\d{8}$")


def disk_percent(client: OpenSearchClient) -> tuple[float, int, int]:
    """Belegung des OpenSearch-Datenträgers in % (Gesamt/Frei in Bytes)."""
    nodes = (client.request("GET", "/_nodes/stats/fs") or {}).get("nodes", {})
    total = sum(int(n.get("fs", {}).get("total", {}).get("total_in_bytes", 0)) for n in nodes.values())
    free = sum(int(n.get("fs", {}).get("total", {}).get("available_in_bytes", 0)) for n in nodes.values())
    if total <= 0:
        raise OpenSearchUnavailable("keine Datenträgerangaben")
    return (total - free) * 100.0 / total, total, free


def level(percent: float) -> str:
    return "emergency" if percent >= EMERGENCY_PERCENT else "warn" if percent >= WARN_PERCENT else "ok"


def deletion_candidates(index_names: list[str], today: str) -> list[str]:
    """Löschreihenfolge: Kategorie nach DELETE_ORDER, darin der älteste Index zuerst; heutiger Index bleibt."""
    parsed: list[tuple[int, str, str]] = []
    for name in index_names:
        m = _INDEX.match(name)
        if not m or m.group(1) not in DELETE_ORDER or m.group(2) >= today:
            continue
        parsed.append((DELETE_ORDER.index(m.group(1)), m.group(2), name))
    return [n for _, _, n in sorted(parsed)]


def guard_cycle(client: OpenSearchClient, now: datetime,
                on_delete: Callable[[str, float], None] | None = None) -> dict[str, Any]:
    """Plattenwächter: Belegung messen, ab 85 % älteste Indizes unwichtiger Kategorien löschen."""
    pct, total, free = disk_percent(client)
    result: dict[str, Any] = {"percent": round(pct, 1), "level": level(pct), "total_bytes": total,
                              "free_bytes": free, "deleted": []}
    if pct < EMERGENCY_PERCENT:
        return result
    rows = client.request("GET", "/_cat/indices/siem-*?format=json&h=index") or []
    today = now.strftime("%Y.%m.%d")
    for name in deletion_candidates([str(r.get("index", "")) for r in rows], today)[:MAX_DELETIONS_PER_CYCLE]:
        client.request("DELETE", f"/{name}")
        result["deleted"].append(name)
        pct, _total, _free = disk_percent(client)
        if on_delete:
            on_delete(name, pct)
        if pct < TARGET_PERCENT:
            break
    result["percent"] = round(pct, 1)
    result["level"] = level(pct)
    return result


def backup_db(db_path: Path, backup_dir: Path, now: datetime, keep: int = KEEP_DB_BACKUPS) -> dict[str, Any]:
    """Konsistente Kopie der Config-DB (``VACUUM INTO``), Integritätsprüfung der Kopie, Rotation."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"siem-{now.strftime('%Y%m%d-%H%M%S')}.db"
    if target.exists():
        target.unlink()
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    try:
        src.execute("VACUUM INTO ?", (str(target),))
    finally:
        src.close()
    os.chmod(target, 0o600)
    check = _integrity(target)
    if check != "ok":
        target.unlink(missing_ok=True)
        raise RuntimeError(f"Sicherung fehlerhaft: {check}")
    files = sorted(p for p in backup_dir.iterdir() if _BACKUP.match(p.name))
    removed = []
    for old in files[:-keep] if keep > 0 else []:
        old.unlink()
        removed.append(old.name)
    return {"file": target.name, "bytes": target.stat().st_size, "removed": removed}


def _integrity(path: Path) -> str:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    try:
        rows = [r[0] for r in con.execute("PRAGMA integrity_check").fetchall()]
    finally:
        con.close()
    return "ok" if rows == ["ok"] else "; ".join(str(r) for r in rows[:3])


def check_db(db_path: Path) -> dict[str, Any]:
    result = _integrity(db_path)
    if result != "ok":
        raise RuntimeError(f"Integritätsprüfung: {result}")
    return {"result": "ok", "bytes": db_path.stat().st_size}


def snapshot_cycle(client: OpenSearchClient, now: datetime, keep: int = KEEP_SNAPSHOTS) -> dict[str, Any]:
    """Tägliche Snapshots der Ereignis-Indizes in das lokale Repository; Rotation nach ``keep``."""
    client.request("PUT", f"/_snapshot/{REPO}", {"type": "fs", "settings": {
        "location": "/usr/share/opensearch/snapshots", "compress": True}})
    name = f"daily-{now.strftime('%Y%m%d')}"
    existing = (client.request("GET", f"/_snapshot/{REPO}/_all") or {}).get("snapshots", [])
    names = sorted(s["snapshot"] for s in existing if _SNAP.match(str(s.get("snapshot", ""))))
    created = False
    if name not in names:
        client.request("PUT", f"/_snapshot/{REPO}/{name}?wait_for_completion=false",
                       {"indices": "siem-*", "ignore_unavailable": True, "include_global_state": False})
        names.append(name)
        created = True
    removed = []
    for old in names[:-keep]:
        client.request("DELETE", f"/_snapshot/{REPO}/{old}")
        removed.append(old)
    return {"snapshot": name, "created": created, "removed": removed}


def in_window(now: datetime) -> bool:
    return WINDOW_START <= now.hour < WINDOW_END


class Scheduler(threading.Thread):
    """Führt die Jobs aus; ``run_job`` ist auch für manuelle Läufe aus dem Web-UI nutzbar."""

    def __init__(self, *, db_path: Path | None, backup_dir: Path, client: OpenSearchClient,
                 report: Callable[[str, str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now().astimezone()) -> None:
        super().__init__(daemon=True, name="maintenance")
        self.db_path = db_path
        self.backup_dir = backup_dir
        self.client = client
        self.report = report or (lambda *_a: None)
        self.clock = clock
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.state_path = backup_dir / "maintenance.json"

    # ---- Zustand ----
    def state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, job: str, ok: bool, detail: dict[str, Any] | str, now: datetime) -> None:
        data = self.state()
        data[job] = {"at": now.astimezone(UTC).isoformat(timespec="seconds"), "ok": ok, "detail": detail,
                     "day": now.strftime("%Y-%m-%d"), "week": now.strftime("%G-%V")}
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), "utf-8")
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    # ---- Jobs ----
    def run_job(self, job: str) -> dict[str, Any]:
        if job not in JOBS:
            raise ValueError(job)
        now = self.clock()
        with self.lock:
            try:
                if job == "guard":
                    detail = guard_cycle(self.client, now, lambda n, p: self.report(
                        "maintenance.emergency_delete", "success", {"index": n, "disk_percent": round(p, 1)}))
                elif job == "snapshot":
                    detail = snapshot_cycle(self.client, now)
                elif self.db_path is None:
                    raise RuntimeError("Config-DB ist keine SQLite-Datei")
                elif job == "db_backup":
                    detail = backup_db(self.db_path, self.backup_dir, now)
                else:
                    detail = check_db(self.db_path)
                ok = True
            except (OpenSearchUnavailable, RuntimeError, OSError, sqlite3.Error) as exc:
                ok, detail = False, str(exc)[:300]
            self._save(job, ok, detail, now)
        if not ok:
            self.report(f"maintenance.{job}", "failure", {"error": detail})
        elif job == "guard" and isinstance(detail, dict) and detail["level"] != "ok":
            self.report("maintenance.disk_" + detail["level"], "failure", {"disk_percent": detail["percent"]})
        return {"ok": ok, "detail": detail}

    def due(self, now: datetime) -> list[str]:
        """Im Wartungsfenster fällige Jobs: Sicherung/Snapshot täglich, Integritätsprüfung sonntags."""
        if not in_window(now):
            return []
        state = self.state()
        today, week = now.strftime("%Y-%m-%d"), now.strftime("%G-%V")
        jobs = []
        for job in ("db_backup", "snapshot"):
            if state.get(job, {}).get("day") != today:
                jobs.append(job)
        if now.weekday() == 6 and state.get("db_integrity", {}).get("week") != week:
            jobs.append("db_integrity")
        return jobs

    def run(self) -> None:
        next_guard = 0.0
        while not self.stop.wait(30):
            now = self.clock()
            ts = now.timestamp()
            if ts >= next_guard:
                next_guard = ts + GUARD_INTERVAL
                self.run_job("guard")
            for job in self.due(now):
                if job == "snapshot" and self.state().get("guard", {}).get("detail", {}).get("level") == "emergency":
                    continue  # bei knappem Speicher keine zusätzlichen Snapshots
                self.run_job(job)
