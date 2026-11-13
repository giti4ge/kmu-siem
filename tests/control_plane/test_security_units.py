"""Bausteine: Verschlüsselung, Kennwortrichtlinie, TOTP, Schlüsseldateien, Migrationen, CLI."""

from __future__ import annotations

import os
import stat
import sys

import pyotp
import pytest
from sqlalchemy import create_engine

from siem_api import cli
from siem_api.db import migrate
from siem_api.models import Base
from siem_api.security import crypto, passwords, totp
from siem_api.security.keys import load_or_create_key


def test_crypto_roundtrip_and_context_binding():
    key = os.urandom(32)
    blob = crypto.encrypt(key, "geheim", "smtp")
    assert b"geheim" not in blob
    assert crypto.decrypt(key, blob, "smtp") == "geheim"
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, blob, "teams")  # anderes Geheimnis
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(os.urandom(32), blob, "smtp")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, tampered, "smtp")


def test_key_file_created_once(tmp_path):
    k1 = load_or_create_key(tmp_path / "s" / "master.key")
    k2 = load_or_create_key(tmp_path / "s" / "master.key")
    assert k1 == k2 and len(k1) == 32
    if sys.platform != "win32":
        assert stat.S_IMODE((tmp_path / "s" / "master.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "s").stat().st_mode) == 0o700


@pytest.mark.parametrize("pw,err", [
    ("kurz", "password_too_short"),
    ("password1234", "password_too_weak"),
    ("qwertzuiop12", "password_too_weak"),
    ("ana-ist-die-beste-2026", "password_contains_username"),
    ("x" * 257, "password_too_long"),
])
def test_policy_rejects(pw, err):
    with pytest.raises(passwords.PolicyError) as exc:
        passwords.check_policy(pw, "ana")
    assert exc.value.args[0] == err


def test_policy_accepts_strong():
    passwords.check_policy("Gruene-Wiese-am-Fluss-2026!", "ana")


def test_argon2id_hash():
    h = passwords.hash_password("Gruene-Wiese-am-Fluss-2026!")
    assert h.startswith("$argon2id$")
    assert passwords.verify_password(h, "Gruene-Wiese-am-Fluss-2026!")
    assert not passwords.verify_password(h, "falsch")
    assert not passwords.verify_password(None, "dummy-password-for-timing")


def test_totp_window_and_replay():
    secret = pyotp.random_base32()
    t = 1_800_000_000
    code = pyotp.TOTP(secret).at(t)
    step = totp.verify(secret, code, None, now=t)
    assert step == t // 30
    assert totp.verify(secret, code, step, now=t) is None          # Wiederverwendung
    assert totp.verify(secret, code, None, now=t + 30) is not None  # ±1 Schritt
    assert totp.verify(secret, code, None, now=t + 90) is None      # zu alt
    assert totp.verify(secret, "abc123", None, now=t) is None


def test_migrations_match_models(tmp_path):
    """Alembic-Schema entspricht dem Modell (keine vergessene Migration)."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    migrate(engine)
    migrate(engine)  # idempotent
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff


def test_cli_create_admin_idempotent(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SIEM_DB_URL", f"sqlite:///{tmp_path / 'c.db'}")
    monkeypatch.setenv("SIEM_SECRETS_DIR", str(tmp_path / "sec"))
    pw = tmp_path / "pw"
    pw.write_text("Gruene-Wiese-am-Fluss-2026!\n")
    assert cli.main(["create-admin", "--password-file", str(pw)]) == 0
    assert '"created": true' in capsys.readouterr().out
    assert cli.main(["create-admin", "--password-file", str(pw)]) == 0
    assert '"created": false' in capsys.readouterr().out
    assert cli.main(["verify-audit"]) == 0
    short = tmp_path / "short"
    short.write_text("kurz")
    assert cli.main(["create-admin", "--username", "zwei", "--password-file", str(short)]) == 2
