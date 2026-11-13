"""Konfiguration aus Umgebungsvariablen (Container) mit sicheren Vorgaben."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Config-DB (SQLite, WAL) – ADR-0008
    db_url: str = field(default_factory=lambda: os.environ.get(
        "SIEM_DB_URL", "sqlite:////opt/siem/data/config-db/siem.db"))
    # Verzeichnis mit Master-Key und Audit-Schlüssel (0700)
    secrets_dir: Path = field(default_factory=lambda: Path(os.environ.get(
        "SIEM_SECRETS_DIR", "/opt/siem/data/secrets/control-plane")))
    # Sitzungen: Leerlauf-Timeout (Spec 5.2a: 30 min, einstellbar) und absolute Höchstdauer
    session_idle_minutes: int = field(default_factory=lambda: _env_int("SIEM_SESSION_IDLE_MINUTES", 30))
    session_max_hours: int = field(default_factory=lambda: _env_int("SIEM_SESSION_MAX_HOURS", 12))
    # Cookies nur über HTTPS (hinter dem Proxy immer der Fall); für Tests abschaltbar
    cookie_secure: bool = field(default_factory=lambda: _env_bool("SIEM_COOKIE_SECURE", True))
    # Kontosperre: ab dieser Zahl Fehlversuche progressive Sperre
    lockout_threshold: int = field(default_factory=lambda: _env_int("SIEM_LOCKOUT_THRESHOLD", 5))
    lockout_max_minutes: int = field(default_factory=lambda: _env_int("SIEM_LOCKOUT_MAX_MINUTES", 60))
    # Anzeigename des TOTP-Ausstellers in Authenticator-Apps
    totp_issuer: str = field(default_factory=lambda: os.environ.get("SIEM_TOTP_ISSUER", "KMU-SIEM"))


def get_settings() -> Settings:
    return Settings()
