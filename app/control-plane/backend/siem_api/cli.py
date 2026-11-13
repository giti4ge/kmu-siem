"""Kommandozeile für Installation und Wartung (im Container: python -m siem_api.cli …).

  create-admin --username NAME (--password-file DATEI | --password-stdin)
      Legt den ersten System-Administrator an (Kennwort aus install.sh). Idempotent:
      existiert der Benutzer bereits, wird nichts geändert. Beim ersten Login ist die
      Einrichtung von TOTP verpflichtend.
  reset-mfa --username NAME
      Notfall: TOTP eines Benutzers zurücksetzen (z. B. einziger Admin hat das Gerät verloren).
      Nur per SSH/siem-hostd erreichbar, wird im Audit-Log protokolliert.
  verify-audit
      Prüft die Hash-Kette des Audit-Logs (Exit 1 bei Manipulation).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

from .audit import AuditLog
from .config import get_settings
from .db import Database, migrate, utcnow
from .models import Role, User
from .security import passwords, rbac, sessions
from .security.keys import KeyRing


def _setup():
    settings = get_settings()
    database = Database(settings.db_url)
    migrate(database.engine)
    keys = KeyRing(settings.secrets_dir)
    with database.sessionmaker() as s:
        rbac.seed_roles(s)
    return database, AuditLog(keys.audit_key, keys.audit_head_file)


def create_admin(username: str, password: str) -> int:
    database, audit = _setup()
    with database.sessionmaker() as db:
        if db.scalars(select(User).where(User.username == username)).first():
            print(json.dumps({"created": False, "username": username}))
            return 0
        # install.sh prüft bereits die Mindestlänge; hier nur als Absicherung
        if len(password) < passwords.MIN_LENGTH:
            print(json.dumps({"error": "password_too_short"}), file=sys.stderr)
            return 2
        admin_role = db.scalars(select(Role).where(Role.name == rbac.SYSTEM_ADMIN)).one()
        user = User(username=username, display_name="Administrator", email="", language="de",
                    password_hash=passwords.hash_password(password), must_change_password=False,
                    enabled=True, totp_enabled=False, failed_logins=0, created_at=utcnow())
        user.roles = [admin_role]
        db.add(user)
        db.commit()
        audit.append(db, actor="install.sh", action="user.create", target=username,
                     details={"roles": [rbac.SYSTEM_ADMIN], "source": "installation"})
    print(json.dumps({"created": True, "username": username}))
    return 0


def reset_mfa(username: str) -> int:
    database, audit = _setup()
    with database.sessionmaker() as db:
        user = db.scalars(select(User).where(User.username == username)).first()
        if user is None:
            print(json.dumps({"error": "not_found"}), file=sys.stderr)
            return 1
        user.totp_enabled = False
        user.totp_secret_enc = None
        user.totp_last_step = None
        sessions.revoke_user_sessions(db, user.id)
        db.commit()
        audit.append(db, actor="cli", action="user.reset_mfa", target=username, details={"source": "cli"})
    print(json.dumps({"reset": True, "username": username}))
    return 0


def verify_audit() -> int:
    database, audit = _setup()
    with database.sessionmaker() as db:
        result = audit.verify(db)
    print(json.dumps(result.__dict__))
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="siem-api")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-admin")
    p.add_argument("--username", default="admin")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--password-file", type=Path)
    src.add_argument("--password-stdin", action="store_true")
    r = sub.add_parser("reset-mfa")
    r.add_argument("--username", required=True)
    sub.add_parser("verify-audit")
    args = parser.parse_args(argv)
    if args.cmd == "create-admin":
        raw = sys.stdin.readline() if args.password_stdin else args.password_file.read_text()
        return create_admin(args.username, raw.strip("\r\n"))
    if args.cmd == "reset-mfa":
        return reset_mfa(args.username)
    return verify_audit()


if __name__ == "__main__":
    sys.exit(main())
