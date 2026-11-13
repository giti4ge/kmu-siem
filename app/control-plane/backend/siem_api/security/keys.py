"""Schlüsselverwaltung: Master-Key (AES-256-GCM) und Audit-Schlüssel (HMAC) im Secrets-Verzeichnis.

Die Dateien werden beim ersten Start mit 0600 angelegt und danach nur gelesen. Sie liegen
auf der Daten-Disk unter data/secrets (0700) und sind Teil des verschlüsselten Backups.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

KEY_BYTES = 32


def load_or_create_key(path: Path) -> bytes:
    """32-Byte-Schlüssel lesen; fehlt die Datei, atomar und exklusiv neu anlegen (0600)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        key = secrets.token_bytes(KEY_BYTES)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # parallel angelegt – vorhandenen Schlüssel verwenden
            return load_or_create_key(path)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        return key
    if len(data) != KEY_BYTES:
        raise RuntimeError(f"Schlüsseldatei {path} ist beschädigt (Länge {len(data)})")
    return data


class KeyRing:
    def __init__(self, secrets_dir: Path):
        self.master_key = load_or_create_key(secrets_dir / "master.key")
        self.audit_key = load_or_create_key(secrets_dir / "audit.key")
        self.audit_head_file = secrets_dir / "audit.head"
