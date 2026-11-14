"""Wartungsjobs: Plattenwächter (Notbereinigung), Config-DB-Sicherung mit Rotation, Snapshots, Zeitplan, Rechte."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from siem_api import maintenance as mt

NOW = datetime(2026, 11, 14, 2, 30).astimezone()  # Samstag im Wartungsfenster


class FakeOS:
    """Minimaler OpenSearch-Ersatz: Datenträger mit Belegung, Indexliste, Snapshots."""

    def __init__(self, used_pct: float, indices: list[str], gb_per_index: float = 10.0) -> None:
        self.total = 1000 * 10**9
        self.used = self.total * used_pct / 100
        self.indices = list(indices)
        self.step = gb_per_index * 10**9
        self.snaps: list[str] = []
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path))
        if path.startswith("/_nodes/stats/fs"):
            return {"nodes": {"n": {"fs": {"total": {"total_in_bytes": self.total,
                                                     "available_in_bytes": int(self.total - self.used)}}}}}
        if path.startswith("/_cat/indices"):
            return [{"index": i} for i in self.indices]
        if method == "DELETE" and path.startswith("/siem-"):
            self.indices.remove(path[1:])
            self.used -= self.step
            return {}
        if path == f"/_snapshot/{mt.REPO}/_all":
            return {"snapshots": [{"snapshot": s} for s in self.snaps]}
        if method == "PUT" and path.startswith(f"/_snapshot/{mt.REPO}/daily-"):
            self.snaps.append(path.split("/")[3].split("?")[0])
        if method == "DELETE" and path.startswith(f"/_snapshot/{mt.REPO}/"):
            self.snaps.remove(path.rsplit("/", 1)[1])
        return {}


def test_levels():
    assert (mt.level(50), mt.level(75), mt.level(85)) == ("ok", "warn", "emergency")


def test_candidates_order_and_protection():
    names = ["siem-audit-2026.01.01", "siem-unparsed-2026.11.01", "siem-windows-2026.10.01",
             "siem-unparsed-2026.10.01", "siem-firewall-2026.11.14", "siem-windows-2026.11.14", "other-x", "siem-ot-2026.01.01"]
    assert mt.deletion_candidates(names, "2026.11.14") == [
        "siem-unparsed-2026.10.01", "siem-unparsed-2026.11.01", "siem-windows-2026.10.01", "siem-audit-2026.01.01"]


def test_guard_ok_and_warn_delete_nothing():
    os_ = FakeOS(80, ["siem-firewall-2026.11.01"])
    r = mt.guard_cycle(os_, NOW)
    assert r["level"] == "warn" and r["deleted"] == []
    assert not [c for c in os_.calls if c[0] == "DELETE"]


def test_guard_emergency_deletes_until_target_and_reports():
    idx = [f"siem-unparsed-2026.10.{d:02d}" for d in range(1, 10)] + ["siem-audit-2026.01.01", "siem-firewall-2026.11.14"]
    os_ = FakeOS(88, idx, gb_per_index=30)  # 88 % → je Löschung -3 Punkte → unter 80 % nach 3 Löschungen
    seen: list[str] = []
    r = mt.guard_cycle(os_, NOW, lambda n, p: seen.append(n))
    assert r["deleted"] == seen == ["siem-unparsed-2026.10.01", "siem-unparsed-2026.10.02", "siem-unparsed-2026.10.03"]
    assert r["percent"] < mt.TARGET_PERCENT and "siem-audit-2026.01.01" in os_.indices
    assert "siem-firewall-2026.11.14" in os_.indices


def test_guard_never_touches_todays_index():
    os_ = FakeOS(95, ["siem-firewall-2026.11.14"])
    r = mt.guard_cycle(os_, NOW)
    assert r["deleted"] == [] and r["level"] == "emergency"


def _make_db(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("create table t(x)")
    con.executemany("insert into t values (?)", [(i,) for i in range(100)])
    con.commit()
    con.close()


def test_backup_rotation_and_integrity(tmp_path: Path):
    db = tmp_path / "siem.db"
    _make_db(db)
    bdir = tmp_path / "bk"
    for sec in range(5):
        r = mt.backup_db(db, bdir, datetime(2026, 11, 14, 2, 0, sec), keep=3)
    files = sorted(p.name for p in bdir.iterdir())
    assert len(files) == 3 and r["file"] == files[-1] and len(r["removed"]) == 1
    copy = sqlite3.connect(bdir / files[-1])
    assert copy.execute("select count(*) from t").fetchone()[0] == 100
    assert mt.check_db(db)["result"] == "ok"


def test_check_db_detects_corruption(tmp_path: Path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    with pytest.raises((RuntimeError, sqlite3.Error)):
        mt.check_db(bad)


def test_snapshot_rotation():
    os_ = FakeOS(10, [])
    os_.snaps = [f"daily-202611{d:02d}" for d in range(1, 9)]  # 8 vorhanden
    r = mt.snapshot_cycle(os_, NOW, keep=7)
    assert r["created"] and r["snapshot"] == "daily-20261114" and r["removed"] == ["daily-20261101", "daily-20261102"]
    assert mt.snapshot_cycle(os_, NOW, keep=7)["created"] is False  # idempotent am selben Tag


def _sched(tmp_path: Path, os_: FakeOS, reports: list, now: datetime = NOW) -> mt.Scheduler:
    db = tmp_path / "siem.db"
    _make_db(db)
    return mt.Scheduler(db_path=db, backup_dir=tmp_path / "bk", client=os_,  # type: ignore[arg-type]
                        report=lambda a, o, d: reports.append((a, o, d)), clock=lambda: now)


def test_due_window_and_once_per_day(tmp_path: Path):
    s = _sched(tmp_path, FakeOS(10, []), [])
    assert s.due(NOW) == ["db_backup", "snapshot"]
    assert s.due(datetime(2026, 11, 14, 12, 0).astimezone()) == []  # außerhalb des Fensters
    s.run_job("db_backup")
    s.run_job("snapshot")
    assert s.due(NOW) == []
    sunday = datetime(2026, 11, 15, 3, 0).astimezone()
    assert "db_integrity" in s.due(sunday) and "db_backup" in s.due(sunday)


def test_failure_is_reported_and_saved(tmp_path: Path):
    reports: list = []
    s = mt.Scheduler(db_path=tmp_path / "missing" / "x.db", backup_dir=tmp_path / "bk", client=FakeOS(10, []),  # type: ignore[arg-type]
                     report=lambda a, o, d: reports.append((a, o, d)), clock=lambda: NOW)
    r = s.run_job("db_backup")
    assert r["ok"] is False and reports[0][:2] == ("maintenance.db_backup", "failure")
    assert s.state()["db_backup"]["ok"] is False


def test_emergency_is_reported(tmp_path: Path):
    reports: list = []
    s = _sched(tmp_path, FakeOS(90, ["siem-unparsed-2026.10.01"], gb_per_index=200), reports)
    s.run_job("guard")
    actions = [r[0] for r in reports]
    assert "maintenance.emergency_delete" in actions


def test_api_status_and_run(app, tmp_path):
    # Router ohne Anmeldung nicht erreichbar
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/maintenance").status_code in (401, 403)
    assert c.post("/api/maintenance/run/guard").status_code in (401, 403)
