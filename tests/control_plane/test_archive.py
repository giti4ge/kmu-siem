"""Revisionssicheres Archiv: Versiegeln, Hash-Kette, Signatur, Manipulationserkennung."""

from __future__ import annotations

import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from siem_api import archive as ar

T0 = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def make(root: Path, cat: str, hour: str, lines: list[dict]) -> Path:
    p = root / cat / "2026/11/14" / f"{hour}.jsonl.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(gzip.compress(b"".join(json.dumps(x).encode() + b"\n" for x in lines)))
    old = (T0 - timedelta(hours=6)).timestamp()
    os.utime(p, (old, old))
    return p


@pytest.fixture()
def arch(tmp_path: Path) -> ar.Archive:
    return ar.Archive(tmp_path, Ed25519PrivateKey.generate(), Clock(T0))


def test_seal_chain_and_verify_ok(arch: ar.Archive) -> None:
    make(arch.root, "firewall", "07", [{"a": 1}])
    make(arch.root, "firewall", "08", [{"a": 2}])
    make(arch.root, "windows", "08", [{"a": 3}])
    assert arch.seal() == {"sealed": 3, "waiting": 0}
    assert arch.seal()["sealed"] == 0  # idempotent
    seals = arch.seals("firewall")
    assert [s["seq"] for s in seals] == [1, 2] and seals[0]["prev"] == ar.GENESIS and seals[1]["prev"] == seals[0]["chain"]
    res = arch.verify()
    assert res["ok"] and res["checked_files"] == 3


def test_open_hour_not_sealed(arch: ar.Archive) -> None:
    p = make(arch.root, "firewall", "09", [{"a": 1}])
    arch.clock.now = datetime(2026, 11, 14, 10, 5, tzinfo=UTC)  # innerhalb der Frist nach Stundenende
    assert arch.seal() == {"sealed": 0, "waiting": 1}
    arch.clock.now = datetime(2026, 11, 14, 10, 20, tzinfo=UTC)
    os.utime(p, (T0.timestamp() - 3600, T0.timestamp() - 3600))
    assert arch.seal()["sealed"] == 1


def test_modified_file_detected(arch: ar.Archive) -> None:
    f = make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    f.write_bytes(gzip.compress(b'{"a": 9}\n'))
    res = arch.verify()
    assert not res["ok"] and res["problems"][0]["problem"] == "file_modified" and res["problems"][0]["file"].endswith("07.jsonl.gz")


def test_deleted_file_detected(arch: ar.Archive) -> None:
    f = make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    f.unlink()
    assert arch.verify()["problems"][0]["problem"] == "file_missing"


def test_removed_or_reordered_seal_detected(arch: ar.Archive) -> None:
    for h in ("05", "06", "07"):
        make(arch.root, "firewall", h, [{"h": h}])
    arch.seal()
    log = arch.root / "_seals" / "firewall.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join([lines[0], lines[2]]) + "\n")  # mittleres Siegel entfernt
    assert any(p["problem"] == "chain_broken" for p in arch.verify()["problems"])


def test_forged_seal_detected(arch: ar.Archive) -> None:
    f = make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    # Angreifer ändert Datei und schreibt Siegel mit eigenem Schlüssel neu
    f.write_bytes(gzip.compress(b'{"a": 9}\n'))
    old = (T0 - timedelta(hours=6)).timestamp()
    os.utime(f, (old, old))
    other =ar.Archive(arch.root, Ed25519PrivateKey.generate(), Clock(T0))
    (arch.root / "_seals" / "firewall.jsonl").unlink()
    other.seal()
    res = arch.verify()  # prüft mit dem Schlüssel der Appliance
    assert any(p["problem"] == "signature_invalid" for p in res["problems"])


def test_unsealed_old_file_reported(arch: ar.Archive) -> None:
    make(arch.root, "firewall", "01", [{"a": 1}])
    res = arch.verify()
    assert not res["ok"] and res["problems"][0]["problem"] == "unsealed_old"


def test_verify_range_limits_file_check(arch: ar.Archive) -> None:
    f = make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    f.write_bytes(b"x")
    assert arch.verify(since="2026-11-15")["ok"]
    assert not arch.verify(since="2026-11-14", until="2026-11-14")["ok"]


def test_key_persisted(tmp_path: Path) -> None:
    k1 = ar.load_or_create_key(tmp_path / "k.pem")
    k2 = ar.load_or_create_key(tmp_path / "k.pem")
    assert ar.public_hex(k1) == ar.public_hex(k2)


def test_worker_reports_failure(arch: ar.Archive, tmp_path: Path) -> None:
    events: list[tuple] = []
    f = make(arch.root, "firewall", "07", [{"a": 1}])
    arch.seal()
    f.write_bytes(b"x")
    w = ar.Worker(arch, tmp_path / "state" / "archive.json", report=lambda *a: events.append(a))
    assert not w.run_verify()["ok"]
    assert events[0][0] == "archive.integrity" and events[0][1] == "failure"
    assert w.state()["verify"]["ok"] is False


def test_api_auth_and_status(app, h, settings):
    from fastapi.testclient import TestClient
    assert TestClient(app).get("/api/archive").status_code in (401, 403)
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    r = c.get("/api/archive")
    assert r.status_code == 200 and len(r.json()["public_key"]) == 64
    assert c.post("/api/archive/verify", json={"since": "morgen"}).status_code == 422
    assert c.post("/api/archive/verify", json={}).json()["ok"] is True
    assert c.post("/api/archive/seal").json()["ok"] is True
