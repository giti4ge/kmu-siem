"""Sophos Central: Normalisierung, Modus/Fallback, Deduplizierung, API (ohne Netzwerk)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem_api import sophos

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path):
    s = sophos.Store(tmp_path, b"k" * 32)
    s.save(enabled=True, client_id="abc-123", mode="auto", client_secret="geheim")
    return s


class FakeCentral:
    licensed = True
    calls: list = []

    def __init__(self, cid, secret):
        assert (cid, secret) == ("abc-123", "geheim")

    def connect(self):
        pass

    def datalake(self, name, frm, to):
        FakeCentral.calls.append(("datalake", name))
        if not FakeCentral.licensed:
            raise sophos.NoLicense("sophos_forbidden")
        return [{"detection_id": "d1", "_kind": f"datalake.{name}", "severity": "high", "hostname": "pc1"}] if name == "detections" else []

    def siem(self, kind, since):
        FakeCentral.calls.append(("siem", kind))
        return [{"id": f"{kind}-1", "_kind": kind, "type": "Event::Endpoint::Threat::Detected", "severity": "high",
                 "location": "pc2", "threat": "Mal/Gen", "created_at": "2026-11-14T11:00:00.000Z", "name": "Malware"}]


def run(store, sent):
    return sophos.run_cycle(store, central_factory=FakeCentral, send=sent.extend, now=NOW)


def test_secret_is_encrypted_at_rest(store):
    assert "geheim" not in store.cfg_path.read_text()
    assert store.secret() == "geheim" and store.config()["has_secret"] is True
    store.save(enabled=False, client_id="abc-123", mode="siem", client_secret=None)  # Secret bleibt erhalten
    assert store.secret() == "geheim" and store.config()["mode"] == "siem"


def test_datalake_primary_and_dedup(store):
    FakeCentral.licensed, FakeCentral.calls, sent = True, [], []
    r = run(store, sent)
    assert r["error"] is None and r["mode"] == "datalake" and r["sent"] == 1
    assert sent[0]["event"]["dataset"] == "sophos.datalake.detections" and sent[0]["siem"]["category"] == "edr"
    sent.clear()
    assert run(store, sent)["sent"] == 0 and sent == []  # Überlappung: bereits gesehen


def test_fallback_to_siem_api_without_license(store):
    FakeCentral.licensed, FakeCentral.calls, sent = False, [], []
    r = run(store, sent)
    assert r["mode"] == "siem" and r["error"] is None and r["sent"] == 2
    assert ("siem", "events") in FakeCentral.calls and ("siem", "alerts") in FakeCentral.calls
    assert sent[0]["siem"]["category"] == "av" and sent[0]["threat"]["indicator"]["name"] == "Mal/Gen"
    assert store.state()["last_mode"] == "siem"


def test_forced_datalake_does_not_fall_back(store):
    store.save(enabled=True, client_id="abc-123", mode="datalake", client_secret=None)
    FakeCentral.licensed, FakeCentral.calls, sent = False, [], []
    r = run(store, sent)
    assert r["error"] == "sophos_forbidden" and sent == [] and not any(c[0] == "siem" for c in FakeCentral.calls)


def test_errors_are_recorded_not_raised(tmp_path):
    s = sophos.Store(tmp_path, b"k" * 32)
    assert sophos.run_cycle(s, central_factory=FakeCentral, send=lambda e: None, now=NOW)["error"] == "sophos_not_configured"
    assert s.state()["last_run"]["error"] == "sophos_not_configured"


def test_http_requires_https():
    with pytest.raises(sophos.SophosError):
        sophos._http("GET", "http://example.org/x")
    with pytest.raises(sophos.SophosError):
        sophos._http("GET", "file:///etc/passwd")


def test_api_never_returns_secret_and_needs_write(h):
    h.create_user("adm", ["system-admin"])
    h.create_user("ana", ["security-analyst"])
    c = h.login("adm")
    r = c.put("/api/sophos/settings", json={"enabled": False, "client_id": "abc-123", "client_secret": "geheim", "mode": "siem"})
    assert r.status_code == 200 and "geheim" not in r.text
    assert r.json()["config"]["has_secret"] is True and r.json()["config"]["mode"] == "siem"
    assert c.get("/api/sophos").status_code == 200
    assert c.put("/api/sophos/settings", json={"enabled": False, "client_id": "a b;", "mode": "siem"}).status_code == 422
    assert h.login("ana").put("/api/sophos/settings", json={"enabled": False, "client_id": "x", "mode": "auto"}).status_code == 403
