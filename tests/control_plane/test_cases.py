"""Fälle: Beweisstücke, Abschluss ins Write-once-Archiv, Unveränderlichkeit, Aufbewahrung."""

from __future__ import annotations

import io
import os
import zipfile
from datetime import UTC, datetime, timedelta

from siem_api import cases as cs
from siem_api.routers import cases as cr


class Fake:
    def request(self, method, path, body=None):
        if path.endswith("/missing"):
            return None
        return {"_source": {"@timestamp": "2026-11-14T10:00:00Z", "user": {"name": "max"}, "message": "x"}}


def test_case_lifecycle(app, h, settings, monkeypatch):
    monkeypatch.setattr(cr, "client_for", lambda _r: Fake())
    h.create_user("ana", ["security-analyst"])
    h.create_user("aud", ["auditor"])
    ana, aud = h.login("ana"), h.login("aud")
    assert aud.post("/api/cases", json={"title": "x"}).status_code == 403  # Auditor nur lesen
    cid = ana.post("/api/cases", json={"title": "Phishing Buchhaltung", "description": "d"}).json()["id"]
    assert ana.post(f"/api/cases/{cid}/notes", json={"text": "Mail geprüft"}).status_code == 200
    ev = {"index": "siem-windows-2026.11.14", "id": "abc123def"}
    assert ana.post(f"/api/cases/{cid}/events", json=ev).status_code == 200
    assert ana.post(f"/api/cases/{cid}/events", json={**ev, "id": "missing"}).status_code == 404
    got = aud.get(f"/api/cases/{cid}").json()
    assert [i["kind"] for i in got["items"]] == ["note", "event"]
    res = ana.post(f"/api/cases/{cid}/close").json()
    assert len(res["sha256"]) == 64
    pkg = settings.archive_dir / "_cases" / str(cid) / "package.zip"
    assert pkg.is_file() and not os.access(pkg, os.W_OK) or os.name == "nt"
    # unveränderlich
    assert ana.post(f"/api/cases/{cid}/notes", json={"text": "spät"}).status_code == 409
    assert ana.post(f"/api/cases/{cid}/close").status_code == 409
    r = aud.get(f"/api/cases/{cid}/package")
    assert r.status_code == 200 and r.headers["X-Package-SHA256"] == res["sha256"]
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        assert {"events.jsonl", "manifest.json", "manifest.sig"} == set(z.namelist())
        assert b"Mail gepr" in z.read("manifest.json")
    # Manipulation des Fallarchivs wird beim Abruf erkannt
    os.chmod(pkg, 0o644)
    pkg.write_bytes(b"manipuliert")
    assert aud.get(f"/api/cases/{cid}/package").status_code == 409


def test_privacy_mode_hides_event_content(app, h, monkeypatch):
    monkeypatch.setattr(cr, "client_for", lambda _r: Fake())
    h.create_user("ana", ["security-analyst"])
    h.create_user("aud", ["auditor"])
    app.state.privacy.set_enabled(True)
    ana, aud = h.login("ana"), h.login("aud")
    cid = ana.post("/api/cases", json={"title": "t"}).json()["id"]
    ana.post(f"/api/cases/{cid}/events", json={"index": "siem-windows-2026.11.14", "id": "abc123def"})
    ev = [i for i in aud.get(f"/api/cases/{cid}").json()["items"] if i["kind"] == "event"][0]
    assert ev["content"] is None


def test_purge_after_retention(app, h, settings, monkeypatch):
    monkeypatch.setattr(cr, "client_for", lambda _r: Fake())
    h.create_user("ana", ["security-analyst"])
    ana = h.login("ana")
    cid = ana.post("/api/cases", json={"title": "t", "retention_months": 1}).json()["id"]
    ana.post(f"/api/cases/{cid}/close")
    with h.db() as db:
        assert cs.purge_expired(db, settings.archive_dir) == []
        later = datetime.now(UTC) + timedelta(days=62)
        assert cs.purge_expired(db, settings.archive_dir, later) == [cid]
    assert not (settings.archive_dir / "_cases" / str(cid)).exists()
    assert ana.get(f"/api/cases/{cid}").status_code == 404
