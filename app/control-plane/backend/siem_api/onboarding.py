"""Anbindungs-Assistent mit Zertifikaten (TLS-Syslog, Port 6514): CA-Zertifikat und Konfigurationsausschnitte."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class OnboardingError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def ca_info(secrets_dir: Path) -> dict[str, Any]:
    try:
        pem = (secrets_dir / "opensearch-ca.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(pem)
    except (OSError, ValueError):
        raise OnboardingError("onboarding_no_ca") from None
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"pem": pem.decode(), "sha256": hashlib.sha256(der).hexdigest(),
            "subject": cert.subject.rfc4514_string(), "expires": cert.not_valid_after_utc.isoformat()}


def snippets(host: str, sha256: str) -> dict[str, str]:
    if not _HOST.match(host):
        raise OnboardingError("onboarding_bad_host")
    return {
        "fortigate": (
            "# 1. CA-Zertifikat unter System > Zertifikate > Importieren > CA-Zertifikat hinterlegen (Datei ca.crt)\n"
            "config log syslogd setting\n    set status enable\n"
            f"    set server \"{host}\"\n    set mode reliable\n    set port 6514\n"
            "    set enc-algorithm high\n    set format default\nend\n"),
        "linux": (
            "# CA-Zertifikat nach /etc/rsyslog.d/siem-ca.crt kopieren, dann /etc/rsyslog.d/90-siem.conf:\n"
            "global(DefaultNetstreamDriver=\"gtls\" DefaultNetstreamDriverCAFile=\"/etc/rsyslog.d/siem-ca.crt\")\n"
            f"*.* action(type=\"omfwd\" target=\"{host}\" port=\"6514\" protocol=\"tcp\"\n"
            "    StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\"\n"
            f"    StreamDriverPermittedPeers=\"{host}\")\n# danach: systemctl restart rsyslog\n"),
        "check": (
            f"# Prüfung vom Gerät/Server aus (Fingerabdruck der CA: {sha256}):\n"
            f"openssl s_client -connect {host}:6514 -CAfile ca.crt </dev/null | grep -E 'Verify return|subject'\n"),
    }
