"""Kommandozeile für Installation und Wartung (im Container: python -m siem_api.cli …).

  create-admin --username NAME --password-file DATEI
      Legt den ersten System-Administrator an (Kennwort aus install.sh). Idempotent:
      existiert der Benutzer bereits, wird nichts geändert. Beim ersten Login ist die
      Einrichtung von TOTP verpflichtend.
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
from .security import passwords, rbac
from .security.keys import KeyRing


def _setup():
    settings = get_settings()
    database = Database(settings.db_url)
    migrate(database.engine)
    keys = KeyRing(settings.secrets_dir)
    with database.sessionmaker() as s:
        rbac.seed_roles(s)
    return database, AuditLog(keys.audit_key, keys.audit_head_file)


def create_admin(username: str, password_file: Path) -> int:
    database, audit = _setup()
    password = password_file.read_text().strip("\r\n")
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
    p.add_argument("--password-file", type=Path, required=True)
    sub.add_parser("verify-audit")
    args = parser.parse_args(argv)
    if args.cmd == "create-admin":
        return create_admin(args.username, args.password_file)
    return verify_audit()


if __name__ == "__main__":
    sys.exit(main())
