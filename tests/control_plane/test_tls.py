"""Web-Zertifikat per PFX: Umwandlung, Rechte, Weitergabe an siem-hostd, Fehlerabbildung."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from siem_api import hostd
from siem_api.routers import tls as tls_router


def _cert(cn, key, issuer=None, issuer_key=None, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject if issuer else name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(issuer_key or key, hashes.SHA256())


def make_pfx(password: str = "geheim", with_key: bool = True) -> bytes:  # noqa: S107
    ca_key, leaf_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    ca = _cert("Test-CA", ca_key, ca=True)
    leaf = _cert("siem.firma.at", leaf_key, ca, ca_key)
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"x", leaf_key if with_key else None, leaf, [ca], enc)


def test_pfx_to_pem_orders_chain_and_exports_pkcs8():
    chain, key = tls_router.pfx_to_pem(make_pfx(), "geheim")
    certs = x509.load_pem_x509_certificates(chain.encode())
    assert [c.subject.rfc4514_string() for c in certs] == ["CN=siem.firma.at", "CN=Test-CA"]
    assert key.startswith("-----BEGIN PRIVATE KEY-----")


def test_bad_password_and_garbage():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        tls_router.pfx_to_pem(make_pfx(), "falsch")
    assert e.value.detail["error"] == "tls_bad_pfx"
    with pytest.raises(HTTPException):
        tls_router.pfx_to_pem(b"kein pfx", "")


def test_install_flow_and_rights(h, monkeypatch):
    calls = []

    def fake(_sock, action, params, actor, timeout=30.0):
        calls.append((action, params))
        return {"scheduled": True, "subject": "CN=siem.firma.at", "fingerprint": "AA:BB"}

    monkeypatch.setattr(hostd, "call", fake)
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    body = {"pfx_b64": base64.b64encode(make_pfx()).decode(), "password": "geheim"}
    r = c.post("/api/tls/pfx", json=body)
    assert r.status_code == 200 and r.json()["scheduled"]
    action, params = calls[-1]
    assert action == "tls.install" and params["key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert "BEGIN CERTIFICATE" in params["chain_pem"]
    assert c.post("/api/tls/pfx", json={**body, "password": "x"}).status_code == 400
    assert c.post("/api/tls/rollback").status_code == 200 and calls[-1][0] == "tls.rollback"
    assert c.post("/api/tls/reset").status_code == 200 and calls[-1][0] == "tls.reset"
    assert c.get("/api/tls").status_code == 200
    h.create_user("aud", ["auditor"])
    a = h.login("aud")
    assert a.post("/api/tls/pfx", json=body).status_code == 403


def test_hostd_rejection_mapped(h, monkeypatch):
    def fake(*_a, **_k):
        raise hostd.HostdRejected("Der private Schlüssel passt nicht zum Zertifikat")

    monkeypatch.setattr(hostd, "call", fake)
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    r = c.post("/api/tls/pfx", json={"pfx_b64": base64.b64encode(make_pfx()).decode(), "password": "geheim"})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "tls_key_mismatch"
