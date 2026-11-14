"""Vier-Augen-Prinzip: Antrag, Freigabe durch andere Person, einmalige Einlösung, Aufdeckung von Pseudonymen."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from siem_api import approvals as ap


def test_store_flow(tmp_path: Path) -> None:
    s = ap.Store(tmp_path / "a.json")
    assert not s.enabled()
    it = s.create("archive.restore", {"c": "x"}, "alice")
    assert s.create("archive.restore", {"c": "x"}, "alice")["id"] == it["id"]  # wiederverwendet
    with pytest.raises(PermissionError):
        s.decide(it["id"], "alice", True, {"archive:approve"})  # nicht selbst
    with pytest.raises(PermissionError):
        s.decide(it["id"], "bob", True, {"logs:approve"})  # falsche Berechtigung
    s.decide(it["id"], "bob", True, {"archive:approve"})
    assert not s.consume(it["id"], "archive.restore", {"c": "y"}, "alice")  # andere Parameter
    assert not s.consume(it["id"], "archive.restore", {"c": "x"}, "mallory")  # andere Person
    assert s.consume(it["id"], "archive.restore", {"c": "x"}, "alice")
    assert not s.consume(it["id"], "archive.restore", {"c": "x"}, "alice")  # einmalig


def test_expiry(tmp_path: Path) -> None:
    s = ap.Store(tmp_path / "a.json")
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    it = s.create("alert.close", {"a": 1}, "alice", now=t0)
    with pytest.raises(ValueError):
        s.decide(it["id"], "bob", True, {"alerts:approve"}, now=t0 + timedelta(hours=25))


def test_api_gate_and_reveal(app, h, monkeypatch):
    h.create_user("adm", ["system-admin"])
    h.create_user("ana", ["security-analyst"])
    h.create_user("dpo", ["privacy-officer"])
    adm, ana, dpo = h.login("adm"), h.login("ana"), h.login("dpo")
    body = {"category": "firewall", "since": "2026-11-14", "until": "2026-11-14"}
    # ohne Vier-Augen-Prinzip: kein 409 (hier 422, weil das Archiv leer ist)
    assert ana.post("/api/archive/restores", json=body).status_code in (403, 422)
    assert adm.put("/api/approvals/config", json={"enabled": True}).status_code == 200
    r = adm.post("/api/archive/restores", json=body)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "approval_required"
    rid = r.json()["detail"]["approval_id"]
    assert adm.post(f"/api/approvals/{rid}/approve").status_code == 403  # Admin ist weder Freigeber noch Antragsteller
    assert dpo.post(f"/api/approvals/{rid}/approve").status_code == 200
    assert len(dpo.get("/api/approvals").json()) == 1
    # eingelöst: Archiv ist leer → 422 statt 409
    assert adm.post("/api/archive/restores", json={**body, "approval_id": rid}).status_code == 422
    assert adm.post("/api/archive/restores", json={**body, "approval_id": rid}).status_code == 409  # verbraucht

    # Aufdeckung
    pseudo = app.state.privacy.pseudo("max.mustermann")

    class Fake:
        def search(self, index, body):
            return {"aggregations": {"u": {"buckets": [{"key": "max.mustermann"}, {"key": "anna"}]}}}

    from siem_api.routers import approvals as ar
    monkeypatch.setattr(ar, "client_for", lambda _r: Fake())
    assert adm.put("/api/approvals/config", json={"enabled": False}).status_code == 200
    assert ana.post("/api/approvals/reveal", json={"pseudonym": pseudo}).status_code == 403
    assert dpo.post("/api/approvals/reveal", json={"pseudonym": pseudo, "reason": "Vorfall"}).json() == {"name": "max.mustermann"}
    assert dpo.post("/api/approvals/reveal", json={"pseudonym": "user_00000000"}).status_code == 404
