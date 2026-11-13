"""Gemeinsame Test-Hilfen: App mit temporärer DB, Benutzer anlegen, Anmelden inkl. TOTP."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "control-plane" / "backend"))

from siem_api.config import Settings  # noqa: E402
from siem_api.db import utcnow  # noqa: E402
from siem_api.main import create_app  # noqa: E402
from siem_api.models import Role, User  # noqa: E402
from siem_api.security import crypto, passwords  # noqa: E402

PASSWORD = "Gruene-Wiese-am-Fluss-2026!"  # noqa: S105 – Testkennwort


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(db_url=f"sqlite:///{tmp_path / 'siem.db'}", secrets_dir=tmp_path / "secrets",
                    cookie_secure=False, session_idle_minutes=30, session_max_hours=12,
                    lockout_threshold=5, lockout_max_minutes=60, totp_issuer="Test", wec_dir=tmp_path / "wec", vector_dir=tmp_path / "vector")


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


class Harness:
    """Benutzer anlegen und als dieser angemeldete Clients erzeugen."""

    def __init__(self, app):
        self.app = app
        self.st = app.state.siem
        self._totp: dict[str, str] = {}

    def db(self):
        return self.st.db.sessionmaker()

    def create_user(self, username: str, roles: list[str], *, password: str = PASSWORD, totp: bool | None = None,
                    must_change: bool = False) -> User:
        with self.db() as db:
            role_objs = [db.query(Role).filter_by(name=r).one() for r in roles]
            user = User(username=username, display_name=username, email="", language="de",
                        password_hash=passwords.hash_password(password), must_change_password=must_change,
                        enabled=True, totp_enabled=False, failed_logins=0, created_at=utcnow())
            user.roles = role_objs
            db.add(user)
            db.commit()
            need_totp = totp if totp is not None else any(r.mfa_required for r in role_objs)
            if need_totp:
                secret = pyotp.random_base32()
                user.totp_secret_enc = crypto.encrypt(self.st.keys.master_key, secret, f"totp:{user.id}")
                user.totp_enabled = True
                db.commit()
                self._totp[username] = secret
            return user

    def code(self, username: str, offset_steps: int = 0) -> str:
        return pyotp.TOTP(self._totp[username]).at(time.time() + offset_steps * 30)

    def login(self, username: str, password: str = PASSWORD) -> TestClient:
        c = TestClient(self.app)
        r = c.post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        data = r.json()
        c.headers["X-CSRF-Token"] = data["csrf_token"]
        if data["stage"] == "mfa_verify":
            r = c.post("/api/auth/totp/verify", json={"code": self.code(username)})
            assert r.status_code == 200, r.text
            data = r.json()
        c.stage = data["stage"]
        return c


@pytest.fixture
def h(app) -> Harness:
    return Harness(app)
