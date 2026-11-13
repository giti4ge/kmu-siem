"""Kennwörter: Argon2id-Hashes und Kennwortrichtlinie (Spec 5.1, 5.2a).

Richtlinie: mindestens 12 Zeichen, höchstens 256, nicht gleich/enthalten im Benutzernamen,
und ausreichend stark laut zxcvbn (Score ≥ 3). zxcvbn enthält Wörterbücher der häufigsten
Kennwörter aus öffentlichen Datenlecks – damit werden kompromittierte Standardkennwörter
offline abgelehnt (die Appliance soll keine Kennwort-Hashes an externe Dienste senden).
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from zxcvbn import zxcvbn

MIN_LENGTH = 12
MAX_LENGTH = 256
MIN_SCORE = 3

# OWASP-Empfehlung für Argon2id (m=19 MiB, t=2, p=1) mit Reserve
_hasher = PasswordHasher(time_cost=3, memory_cost=19456, parallelism=1)
# Vergleichshash für unbekannte Benutzer (gleiche Laufzeit wie bei echten Konten)
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


class PolicyError(ValueError):
    """Kennwort entspricht nicht der Richtlinie; args[0] = Fehlercode für die UI-Übersetzung."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def check_policy(password: str, username: str = "", extra_words: list[str] | None = None) -> None:
    if len(password) < MIN_LENGTH:
        raise PolicyError("password_too_short")
    if len(password) > MAX_LENGTH:
        raise PolicyError("password_too_long")
    if username and username.lower() in password.lower():
        raise PolicyError("password_contains_username")
    # zxcvbn nur auf die ersten 100 Zeichen (Laufzeit)
    result = zxcvbn(password[:100], user_inputs=[username, *(extra_words or []), "siem", "kmu"])
    if result["score"] < MIN_SCORE:
        raise PolicyError("password_too_weak")
