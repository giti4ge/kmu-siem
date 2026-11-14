"""Linux-Anbindung (agentlos): Onboarding-Skript für rsyslog (Syslog-TLS 6514) und optional auditd."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

SYSLOG_TLS_PORT = 6514
_SERVER = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class LinuxOnboardingError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_server(value: str) -> str:
    """Hostname oder IPv4 der Appliance; nur Zeichen, die im Shell-Skript unkritisch sind."""
    v = (value or "").strip()
    if not _SERVER.match(v):
        raise LinuxOnboardingError("linux_invalid_server")
    return v


def read_ca(secrets_dir: Path) -> str:
    try:
        pem = (secrets_dir / "opensearch-ca.crt").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise LinuxOnboardingError("linux_ca_unavailable") from exc
    lines = [ln.strip() for ln in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN CERTIFICATE-----" or lines[-1] != "-----END CERTIFICATE-----":
        raise LinuxOnboardingError("linux_ca_unavailable")
    if not all(re.fullmatch(r"[A-Za-z0-9+/=]+", ln) for ln in lines[1:-1]):
        raise LinuxOnboardingError("linux_ca_unavailable")
    return "\n".join(lines) + "\n"


AUDIT_RULES = """\
# KMU-SIEM – auditd-Regeln (Benutzer, sudo, SSH, Dateiänderungen an Konfiguration)
-w /etc/passwd -p wa -k siem_identity
-w /etc/shadow -p wa -k siem_identity
-w /etc/group -p wa -k siem_identity
-w /etc/gshadow -p wa -k siem_identity
-w /etc/sudoers -p wa -k siem_sudo
-w /etc/sudoers.d/ -p wa -k siem_sudo
-w /etc/ssh/sshd_config -p wa -k siem_ssh
-w /etc/ssh/sshd_config.d/ -p wa -k siem_ssh
-w /root/.ssh/ -p wa -k siem_ssh
-w /etc/crontab -p wa -k siem_cron
-w /etc/cron.d/ -p wa -k siem_cron
-w /etc/systemd/system/ -p wa -k siem_systemd
-w /etc/rsyslog.d/ -p wa -k siem_logging
-w /etc/audit/ -p wa -k siem_logging
"""

_TEMPLATE = r"""#!/bin/sh
# KMU-SIEM – Linux-Onboarding (agentlos, rsyslog -> Syslog-TLS)
# Ziel: @@SERVER@@:@@PORT@@   Audit-Regeln: @@AUDIT@@
# Idempotent; sichert geänderte Dateien als *.siem-bak. Ausführen als root.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen." >&2; exit 1; }
SERVER='@@SERVER@@'
PORT=@@PORT@@
WITH_AUDIT=@@AUDIT_FLAG@@

if command -v apt-get >/dev/null 2>&1; then PM=apt; CA_DIR=/etc/ssl/certs; GTLS=rsyslog-gnutls
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then PM=rpm; CA_DIR=/etc/pki/tls/certs; GTLS=rsyslog-gnutls
elif command -v zypper >/dev/null 2>&1; then PM=suse; CA_DIR=/etc/ssl/certs; GTLS=rsyslog-module-gtls
else echo "Nicht unterstützte Distribution (apt, dnf/yum, zypper)." >&2; exit 1; fi

install_pkg() {
    case $PM in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        rpm) if command -v dnf >/dev/null 2>&1; then dnf install -y "$@"; else yum install -y "$@"; fi ;;
        suse) zypper --non-interactive install "$@" ;;
    esac
}

echo "[1/4] Pakete"
[ "$PM" = apt ] && apt-get update -qq
install_pkg rsyslog "$GTLS"

echo "[2/4] CA-Zertifikat der Appliance"
CA_FILE="$CA_DIR/siem-appliance-ca.pem"
cat > "$CA_FILE" <<'SIEM_CA_EOF'
@@CA@@SIEM_CA_EOF
chmod 0644 "$CA_FILE"

echo "[3/4] rsyslog-Weiterleitung"
CONF=/etc/rsyslog.d/90-siem.conf
[ -f "$CONF" ] && cp -p "$CONF" "$CONF.siem-bak"
cat > "$CONF" <<SIEM_CONF_EOF
# KMU-SIEM – Weiterleitung per TLS (verwaltet durch das Onboarding-Skript)
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="$CA_FILE"
)
*.* action(
  type="omfwd" target="$SERVER" port="$PORT" protocol="tcp"
  template="RSYSLOG_SyslogProtocol23Format"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/certvalid"
  action.resumeRetryCount="-1"
  queue.type="LinkedList" queue.filename="siem_fwd" queue.maxDiskSpace="512m"
  queue.saveOnShutdown="on" queue.size="50000"
)
SIEM_CONF_EOF
rsyslogd -N1 >/dev/null
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog

echo "[4/4] auditd"
if [ "$WITH_AUDIT" = 1 ]; then
    install_pkg auditd 2>/dev/null || install_pkg audit
    [ "$PM" = apt ] && { install_pkg audispd-plugins 2>/dev/null || true; }
    cat > /etc/audit/rules.d/siem.rules <<'SIEM_AUDIT_EOF'
@@RULES@@SIEM_AUDIT_EOF
    for p in /etc/audit/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf; do
        [ -f "$p" ] && sed -i 's/^active *=.*/active = yes/' "$p"
    done
    augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/siem.rules >/dev/null 2>&1 || true
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
else
    echo "übersprungen"
fi

logger -t siem-onboarding "Linux-Onboarding abgeschlossen auf $(hostname)"
echo "Fertig. Testmeldung gesendet – das Gerät erscheint im SIEM unter Quellen."
"""


def render_script(server: str, ca_pem: str, audit: bool) -> str:
    s = validate_server(server)
    return (
        _TEMPLATE.replace("@@AUDIT_FLAG@@", "1" if audit else "0")
        .replace("@@AUDIT@@", "ja" if audit else "nein")
        .replace("@@SERVER@@", s)
        .replace("@@PORT@@", str(SYSLOG_TLS_PORT))
        .replace("@@CA@@", ca_pem)
        .replace("@@RULES@@", AUDIT_RULES)
    )


def script_sha256(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()
