"""Konfigurations-Snapshots (Redaktion, Änderungserkennung, Diff) und Anbindungs-Assistent (CA, Snippets)."""

from __future__ import annotations

import datetime as dt
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from siem_api import onboarding as ob
from siem_api import snapshots as sn

CONF1 = 'config system admin\n edit "admin"\n set password ENC SH2abcdef==\n next\nend\nset hostname "fw1"\n'
CONF2 = CONF1.replace("fw1", "fw2")


def test_redaction_hides_secrets_but_keeps_change_visible() -> None:
    a = sn.redact(CONF1)
    b = sn.redact(CONF1.replace("SH2abcdef==", "SH2other=="))
    assert "abcdef" not in a and "ENC [sha256:" in a and a != b
    assert sn.redact('set psksecret "klartext"\n') == 'set psksecret "[redacted]"\n'


def test_take_only_stores_changes_and_diffs(tmp_path: Path) -> None:
    s = sn.Store(tmp_path / "snap")
    t0 = datetime(2026, 11, 14, 1, 0, tzinfo=UTC)
    r1 = s.take(lambda: CONF1, now=t0)
    assert r1["changed"] and r1["first"]
    assert s.take(lambda: CONF1, now=t0.replace(hour=2)) == {"changed": False, "name": r1["name"],
                                                           "sha256": r1["sha256"]}
    r2 = s.take(lambda: CONF2, now=t0.replace(hour=3))
    assert r2["changed"] and (r2["added"], r2["removed"]) == (1, 1)
    d = s.diff(r1["name"], r2["name"])
    assert any(ln == '-set hostname "fw1"' for ln in d) and any(ln == '+set hostname "fw2"' for ln in d)
    assert len(s.list()) == 2
    with pytest.raises(sn.SnapshotError):
        s.read("../../etc/passwd")
    with pytest.raises(sn.SnapshotError):
        s.take(lambda: "  ")


def test_api_snapshots(app, h, monkeypatch):
    from siem_api.routers import snapshots as sr
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    assert adm.post("/api/snapshots").status_code == 409  # FortiGate-API nicht aktiv
    app.state.forti_store.save(enabled=True, host="fw.example", port=443, vdom="root", tls_pin="", token="tok")
    monkeypatch.setattr(sr.fg, "api_get_text", lambda *a, **k: CONF1)
    monkeypatch.setattr(sr, "fetch_fortigate", lambda store, get=None: (lambda: CONF1))
    r = adm.post("/api/snapshots")
    assert r.status_code == 200 and r.json()["changed"]
    assert adm.get("/api/snapshots").json()[0]["name"].endswith(".conf")
    assert adm.get("/api/snapshots/diff", params={"a": "x", "b": "y"}).status_code == 404


def _ca(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KMU-SIEM Root CA test")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=100))
            .sign(key, hashes.SHA256()))
    (tmp_path / "opensearch-ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_onboarding(app, h, settings):
    h.create_user("aud", ["auditor"])
    aud = h.login("aud")
    assert aud.get("/api/onboarding/tls").status_code == 409  # keine CA vorhanden
    _ca(settings.secrets_dir)
    r = aud.get("/api/onboarding/tls", headers={"host": "siem.kunde.local"})
    j = r.json()
    assert r.status_code == 200 and j["host"] == "siem.kunde.local" and len(j["ca_sha256"]) == 64
    assert 'set server "siem.kunde.local"' in j["snippets"]["fortigate"] and j["ca_sha256"] in j["snippets"]["check"]
    assert b"BEGIN CERTIFICATE" in aud.get("/api/onboarding/ca.crt").content
    with pytest.raises(ob.OnboardingError):
        ob.snippets("bad host;rm", "x")
