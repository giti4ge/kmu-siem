"""TOTP (RFC 6238, SHA-1, 6 Stellen, 30 s) mit Schutz gegen Wiederverwendung."""

from __future__ import annotations

import time

import pyotp

STEP = 30
VALID_WINDOW = 1  # ±1 Zeitschritt Uhrenabweichung


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Prüft den Code. Rückgabe: akzeptierter Zeitschritt (für totp_last_step) oder None.

    Ein Code wird nur akzeptiert, wenn sein Zeitschritt nach dem zuletzt akzeptierten liegt
    (verhindert das Wiederverwenden eines abgefangenen Codes innerhalb seiner Gültigkeit).
    """
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret)
    current = int(now // STEP)
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if pyotp.utils.strings_equal(totp.at(step * STEP), code):
            return step
    return None
