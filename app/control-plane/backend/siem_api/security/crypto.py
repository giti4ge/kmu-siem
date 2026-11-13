"""AES-256-GCM für Geheimnisse in der Config-DB (Spec 5.1).

Format: b"v1" | Nonce (12 Byte) | Chiffrat+Tag. Der Name des Geheimnisses ist als AAD
gebunden – ein Chiffrat lässt sich nicht unbemerkt einem anderen Eintrag zuordnen.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"v1"
NONCE_BYTES = 12


class DecryptionError(Exception):
    pass


def encrypt(key: bytes, plaintext: str, context: str) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), context.encode())
    return VERSION + nonce + ct


def decrypt(key: bytes, blob: bytes, context: str) -> str:
    if not blob.startswith(VERSION) or len(blob) < len(VERSION) + NONCE_BYTES + 16:
        raise DecryptionError("Unbekanntes Format")
    nonce = blob[len(VERSION):len(VERSION) + NONCE_BYTES]
    try:
        return AESGCM(key).decrypt(nonce, blob[len(VERSION) + NONCE_BYTES:], context.encode()).decode()
    except Exception as exc:  # InvalidTag
        raise DecryptionError("Entschlüsselung fehlgeschlagen") from exc
