"""Anmeldung, MFA, Sperre, CSRF, Sitzungen, Kennwortwechsel."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from conftest import PASSWORD
from siem_api.db import utcnow
from siem_api.models import Session, User


def test_health_without_login(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store"


def test_login_cookie_flags_and_me(h):
    h.create_user("ana", ["security-analyst"])
    c = TestClient(h.app)
    r = c.post("/api/auth/login", json={"username": "ana", "password": PASSWORD})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    body = r.json()
    assert body["stage"] == "ok" and "alerts:read" in body["permissions"]
    assert c.get("/api/auth/me").json()["user"]["username"] == "ana"


def test_secure_cookie_flag_by_default(tmp_path):
    from siem_api.config import Settings
    from siem_api.main import create_app
    app = create_app(Settings(db_url=f"sqlite:///{tmp_path / 'x.db'}", secrets_dir=tmp_path / "s"))
    from conftest import Harness
    Harness(app).create_user("ana", ["auditor"])
    r = TestClient(app).post("/api/auth/login", json={"username": "ana", "password": PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()


def test_login_failure_is_generic(h, client):
    h.create_user("ana", ["auditor"])
    wrong = client.post("/api/auth/login", json={"username": "ana", "password": "falsch-falsch-falsch"})
    unknown = client.post("/api/auth/login", json={"username": "niemand", "password": "falsch-falsch-falsch"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": {"error": "invalid_credentials"}}


def test_no_password_echo_in_validation_errors(client):
    r = client.post("/api/auth/login", json={"username": "ana", "password": "x" * 300})
    assert r.status_code == 422 and "xxxx" not in r.text


def test_progressive_lockout(h, client):
    h.create_user("ana", ["auditor"])
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "ana", "password": "falsch-falsch-falsch"})
    # Gesperrt: auch das richtige Kennwort wird abgewiesen (gleiche Antwort)
    r = client.post("/api/auth/login", json={"username": "ana", "password": PASSWORD})
    assert r.status_code == 401
    with h.db() as db:
        user = db.query(User).filter_by(username="ana").one()
        assert user.failed_logins == 5 and user.locked_until is not None
        user.locked_until = utcnow() - timedelta(seconds=1)  # Sperre abgelaufen
        db.commit()
    assert client.post("/api/auth/login", json={"username": "ana", "password": PASSWORD}).status_code == 200
    with h.db() as db:
        assert db.query(User).filter_by(username="ana").one().failed_logins == 0


def test_lockout_grows(h, client):
    h.create_user("ana", ["auditor"])
    durations = []
    for _ in range(7):
        client.post("/api/auth/login", json={"username": "ana", "password": "falsch-falsch-falsch"})
        with h.db() as db:
            u = db.query(User).filter_by(username="ana").one()
            if u.locked_until:
                durations.append(round((u.locked_until.replace(tzinfo=None) - utcnow().replace(tzinfo=None))
                                       .total_seconds() / 60))
                u.locked_until = None  # nächsten Versuch zulassen
                db.commit()
    assert durations == [1, 2, 4]


def test_totp_required_and_replay_rejected(h):
    h.create_user("adm", ["system-admin"])
    c = TestClient(h.app)
    r = c.post("/api/auth/login", json={"username": "adm", "password": PASSWORD})
    assert r.json()["stage"] == "mfa_verify" and r.json()["permissions"] == []
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    # Vor dem zweiten Faktor keine fachlichen Endpunkte
    assert c.get("/api/users").status_code == 403
    assert c.post("/api/auth/totp/verify", json={"code": "000000"}).status_code == 401
    code = h.code("adm")
    assert c.post("/api/auth/totp/verify", json={"code": code}).json()["stage"] == "ok"
    assert c.get("/api/users").status_code == 200
    # Derselbe Code in einer zweiten Sitzung: abgelehnt (Wiederverwendung)
    c2 = TestClient(h.app)
    r2 = c2.post("/api/auth/login", json={"username": "adm", "password": PASSWORD})
    c2.headers["X-CSRF-Token"] = r2.json()["csrf_token"]
    assert c2.post("/api/auth/totp/verify", json={"code": code}).status_code == 401


def test_admin_without_totp_must_enroll(h):
    import pyotp
    h.create_user("adm", ["system-admin"], totp=False)
    c = TestClient(h.app)
    r = c.post("/api/auth/login", json={"username": "adm", "password": PASSWORD})
    assert r.json()["stage"] == "mfa_enroll"
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert c.get("/api/users").status_code == 403
    setup = c.post("/api/auth/totp/setup").json()
    assert setup["uri"].startswith("otpauth://totp/")
    assert c.post("/api/auth/totp/enable", json={"code": "123456"}).status_code == 400
    r = c.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(setup["secret"]).now()})
    assert r.json()["stage"] == "ok"
    assert c.get("/api/users").status_code == 200
    with h.db() as db:
        u = db.query(User).filter_by(username="adm").one()
        assert u.totp_enabled and setup["secret"].encode() not in u.totp_secret_enc  # verschlüsselt


def test_must_change_password(h):
    h.create_user("ana", ["auditor"], must_change=True)
    c = h.login("ana")
    assert c.stage == "password_change"
    assert c.get("/api/audit").status_code == 403
    weak = c.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "passwort1234"})
    assert weak.status_code == 400 and weak.json()["detail"]["error"] == "password_too_weak"
    short = c.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "kurz"})
    assert short.json()["detail"]["error"] == "password_too_short"
    r = c.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "Blauer-Himmel-ueber-Linz-77"})
    assert r.status_code == 200 and r.json()["stage"] == "ok"
    assert c.get("/api/audit").status_code == 200


def test_password_change_revokes_other_sessions(h):
    h.create_user("ana", ["auditor"])
    c1, c2 = h.login("ana"), h.login("ana")
    r = c1.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "Blauer-Himmel-ueber-Linz-77"})
    assert r.status_code == 200
    assert c1.get("/api/auth/me").status_code == 200
    assert c2.get("/api/auth/me").status_code == 401


def test_csrf_required_for_state_changes(h):
    h.create_user("adm", ["system-admin"])
    c = h.login("adm")
    token = c.headers.pop("X-CSRF-Token")
    body = {"username": "neu", "password": "Ein-sehr-gutes-Kennwort-42", "roles": ["auditor"]}
    assert c.post("/api/users", json=body).json()["detail"]["error"] == "csrf_failed"
    c.headers["X-CSRF-Token"] = "falsch"
    assert c.post("/api/users", json=body).status_code == 403
    c.headers["X-CSRF-Token"] = token
    assert c.post("/api/users", json=body).status_code == 201


def test_session_idle_timeout(h):
    h.create_user("ana", ["auditor"])
    c = h.login("ana")
    with h.db() as db:
        s = db.query(Session).one()
        s.last_seen_at = utcnow() - timedelta(minutes=31)
        db.commit()
    assert c.get("/api/auth/me").status_code == 401
    with h.db() as db:
        assert db.query(Session).count() == 0


def test_session_absolute_timeout(h):
    h.create_user("ana", ["auditor"])
    c = h.login("ana")
    with h.db() as db:
        s = db.query(Session).one()
        s.created_at = utcnow() - timedelta(hours=13)
        db.commit()
    assert c.get("/api/auth/me").status_code == 401


def test_logout(h):
    h.create_user("ana", ["auditor"])
    c = h.login("ana")
    assert c.post("/api/auth/logout").status_code == 204
    assert c.get("/api/auth/me").status_code == 401


def test_disabled_user_cannot_login_and_sessions_end(h):
    h.create_user("adm", ["system-admin"])
    h.create_user("ana", ["auditor"])
    ana = h.login("ana")
    adm = h.login("adm")
    with h.db() as db:
        uid = db.query(User).filter_by(username="ana").one().id
    assert adm.patch(f"/api/users/{uid}", json={"enabled": False}).status_code == 200
    assert ana.get("/api/auth/me").status_code == 401
    assert TestClient(h.app).post("/api/auth/login", json={"username": "ana", "password": PASSWORD}).status_code == 401
