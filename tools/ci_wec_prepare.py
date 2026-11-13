#!/usr/bin/env python3
"""CI-Hilfe: OpenWEC-Konfiguration, Subscriptions und eine Test-Keytab in ein Verzeichnis schreiben."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from siem_api import wec


def fake_keytab(princ: str, realm: str) -> bytes:
    comps = princ.split("/")
    body = struct.pack(">h", len(comps)) + struct.pack(">h", len(realm)) + realm.encode()
    for c in comps:
        body += struct.pack(">h", len(c)) + c.encode()
    body += struct.pack(">iIBhh", 1, 0, 3, 18, 32) + b"k" * 32
    return b"\x05\x02" + struct.pack(">i", len(body)) + body


def main() -> int:
    out = Path(sys.argv[1])
    settings = wec.validate_settings({
        "domain": "firma.local", "fqdn": "siem.firma.local",
        "roles": {"dc": ["OU=Domain Controllers,DC=firma,DC=local"], "member": ["OU=Server,DC=firma,DC=local"]},
    })
    wec.write_all(out, settings)
    wec._write(out / "krb5.keytab", fake_keytab("HTTP/siem.firma.local", "FIRMA.LOCAL"), 0o640)
    return 0


if __name__ == "__main__":
    sys.exit(main())
