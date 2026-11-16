"""Mehrere MFA-Geräte: hinzufügen, Anmeldung mit jedem Gerät, Löschen, Zurücksetzen."""

from __future__ import annotations

import time

import pyotp
from fastapi.testclient import TestClient

from conftest import PASSWORD


def _login_stage1(h, username):
    c = TestClient(h.app)
    r = c.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["stage"] == "mfa_verify"
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def _add(c, name="Handy 2"):
    r = c.post("/api/auth/mfa/devices", json={"name": name})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = c.post("/api/auth/mfa/devices/enable", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return secret, r.json()


def test_add_second_device_and_login_with_it(h):
    h.create_user("anna", ["system-admin"])
    c = h.login("anna")
    secret, view = _add(c)
    assert [d["primary"] for d in view["devices"]] == [True, False]
    assert view["devices"][1]["name"] == "Handy 2"
    # Anmeldung mit dem Code des zweiten Geräts (anderer Zeitschritt als bei der Einrichtung)
    c2 = _login_stage1(h, "anna")
    code = pyotp.TOTP(secret).at(time.time() + 30)
    assert c2.post("/api/auth/totp/verify", json={"code": code}).status_code == 200
    # Wiederverwendung desselben Codes wird abgelehnt
    c3 = _login_stage1(h, "anna")
    assert c3.post("/api/auth/totp/verify", json={"code": code}).status_code == 401
    # das erste Gerät funktioniert weiterhin
    c4 = _login_stage1(h, "anna")
    assert c4.post("/api/auth/totp/verify", json={"code": h.code("anna", 1)}).status_code == 200


def test_wrong_code_does_not_enable_device(h):
    h.create_user("bert", ["system-admin"])
    c = h.login("bert")
    assert c.post("/api/auth/mfa/devices", json={"name": "x"}).status_code == 200
    assert c.post("/api/auth/mfa/devices/enable", json={"code": "000000"}).status_code == 400
    assert len(c.get("/api/auth/mfa/devices").json()["devices"]) == 1


def test_delete_needs_password_and_keeps_last_device(h):
    h.create_user("carl", ["system-admin"])
    c = h.login("carl")
    secret, view = _add(c)
    dev_id = view["devices"][1]["id"]
    assert c.post(f"/api/auth/mfa/devices/{dev_id}/delete", json={"current_password": "falsch"}).status_code == 400
    r = c.post(f"/api/auth/mfa/devices/{dev_id}/delete", json={"current_password": PASSWORD})
    assert r.status_code == 200 and len(r.json()["devices"]) == 1
    # letztes Gerät bleibt
    r = c.post("/api/auth/mfa/devices/0/delete", json={"current_password": PASSWORD})
    assert r.status_code == 409


def test_delete_primary_promotes_second(h):
    h.create_user("dora", ["system-admin"])
    c = h.login("dora")
    secret, _ = _add(c)
    r = c.post("/api/auth/mfa/devices/0/delete", json={"current_password": PASSWORD})
    assert r.status_code == 200 and len(r.json()["devices"]) == 1
    # altes erstes Gerät gilt nicht mehr, das zweite Gerät ist jetzt das erste
    c2 = _login_stage1(h, "dora")
    assert c2.post("/api/auth/totp/verify", json={"code": h.code("dora", 1)}).status_code == 401
    code = pyotp.TOTP(secret).at(time.time() + 30)
    c3 = _login_stage1(h, "dora")
    assert c3.post("/api/auth/totp/verify", json={"code": code}).status_code == 200


def test_requires_login(client):
    assert client.get("/api/auth/mfa/devices").status_code == 401
