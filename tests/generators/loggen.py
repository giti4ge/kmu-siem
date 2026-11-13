#!/usr/bin/env python3
"""Synthetischer Log-Generator für das Testlabor (nur Python-Standardbibliothek).

Erzeugt Syslog-Ereignisse im Stil der unterstützten Quellen und sendet sie per
UDP, TCP oder TLS an die Appliance – oder gibt sie auf stdout aus.

WICHTIG: Es liegen noch keine echten Beispiel-Logs vor (SPEC R-02). Die Formate
sind aus Herstellerdokumentation nachgebildet und dienen nur als Startpunkt für
Parser-Entwicklung und Lasttests. Echte Proben ersetzen sie, sobald verfügbar.

Beispiele:
  loggen.py --list
  loggen.py --source fortigate-traffic --count 5 --stdout
  loggen.py --source all --eps 50 --duration 60 --target 10.0.10.50 --proto udp
  loggen.py --source linux-sshd --target siem.firma.local --port 6514 --proto tls --ca ca.pem
"""

from __future__ import annotations

import argparse
import random
import socket
import ssl
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# Zufallsdaten
# ---------------------------------------------------------------------------
USERS = ["mueller", "huber", "admin", "svc-backup", "wagner", "gruber", "administrator"]
INTERNAL = [f"10.0.{v}.{h}" for v in (10, 20, 30) for h in range(10, 60)]
EXTERNAL = ["8.8.8.8", "1.1.1.1", "185.199.108.153", "20.112.52.29", "45.155.205.233", "91.240.118.172"]
SERVICES = [("DNS", 17, 53), ("HTTPS", 6, 443), ("HTTP", 6, 80), ("SMB", 6, 445), ("RDP", 6, 3389), ("SSH", 6, 22)]
MACS = ["00:50:56:a1:b2:c3", "3c:52:82:11:22:33", "b8:27:eb:44:55:66", "f0:1f:af:77:88:99"]


def rnd(seq):
    return random.choice(seq)


def now() -> datetime:
    return datetime.now(UTC).astimezone()


# ---------------------------------------------------------------------------
# Nachrichten je Quelle: liefern (hostname, app, msg, severity, facility)
# ---------------------------------------------------------------------------
@dataclass
class Event:
    host: str
    app: str
    msg: str
    severity: int = 6  # informational
    facility: int = 16  # local0


def _fgt_head(logid: str, typ: str, sub: str, level: str) -> str:
    t = now()
    return (
        f'date={t:%Y-%m-%d} time={t:%H:%M:%S} devname="FGT-LAB" devid="FGT60FTK0000LAB0" '
        f'eventtime={int(t.timestamp() * 1e9)} tz="{t:%z}" logid="{logid}" type="{typ}" '
        f'subtype="{sub}" level="{level}" vd="root"'
    )


def fortigate_traffic() -> Event:
    name, proto, port = rnd(SERVICES)
    src, dst = rnd(INTERNAL), rnd(INTERNAL + EXTERNAL)
    action = random.choices(["accept", "deny", "close"], weights=[5, 2, 5])[0]
    msg = (
        _fgt_head("0000000013", "traffic", "forward", "notice")
        + f' srcip={src} srcport={random.randint(1024, 65535)} srcintf="vlan10" '
        f'dstip={dst} dstport={port} dstintf="wan1" proto={proto} service="{name}" '
        f'action="{action}" policyid={random.randint(1, 30)} '
        f"sentbyte={random.randint(40, 90000)} rcvdbyte={random.randint(40, 900000)}"
    )
    return Event("FGT-LAB", "", msg, 5, 23)


def fortigate_ips() -> Event:
    msg = (
        _fgt_head("0419016384", "utm", "ips", "alert")
        + f' srcip={rnd(EXTERNAL)} dstip={rnd(INTERNAL)} dstport=445 proto=6 action="dropped" '
        f'attack="MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution" severity="critical"'
    )
    return Event("FGT-LAB", "", msg, 1, 23)


def fortigate_admin() -> Event:
    status = random.choices(["success", "failed"], weights=[4, 1])[0]
    msg = (
        _fgt_head("0100032001", "event", "system", "information")
        + f' user="{rnd(USERS)}" ui="https({rnd(INTERNAL)})" action="login" status="{status}" '
        f'msg="Administrator {rnd(USERS)} logged in {"successfully" if status == "success" else "failed"}"'
    )
    return Event("FGT-LAB", "", msg, 6, 23)


def fortigate_vpn() -> Event:
    msg = (
        _fgt_head("0101039947", "event", "vpn", "information")
        + f' action="tunnel-up" tunneltype="ssl-tunnel" remip={rnd(EXTERNAL)} '
        f'user="{rnd(USERS)}" tunnelip=10.212.134.{random.randint(10, 200)}'
    )
    return Event("FGT-LAB", "", msg, 6, 23)


def arubaos_link() -> Event:
    port = random.randint(1, 48)
    state = rnd(["up", "down"])
    return Event("SW-ARUBA-01", "ports", f"port {port} is now {'on-line' if state == 'up' else 'off-line'}", 5)


def arubaos_auth() -> Event:
    return Event("SW-ARUBA-01", "auth", f"Invalid user name/password on SSH session from {rnd(INTERNAL)}", 4)


def fs_link() -> Event:
    port = random.randint(1, 48)
    state = rnd(["UP", "DOWN"])
    return Event("SW-FS-S3900", "%LINK-5-CHANGED", f"Interface eth1/0/{port}, changed state to {state}", 5)


def linux_sshd() -> Event:
    ip = rnd(INTERNAL + EXTERNAL)
    if random.random() < 0.6:
        msg = f"Failed password for {rnd(USERS)} from {ip} port {random.randint(30000, 65000)} ssh2"
        sev = 4
    else:
        msg = f"Accepted publickey for {rnd(USERS)} from {ip} port {random.randint(30000, 65000)} ssh2"
        sev = 6
    return Event("srv-linux-01", "sshd", msg, sev, 4)


def linux_sudo() -> Event:
    u = rnd(USERS)
    msg = f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    return Event("srv-linux-01", "sudo", msg, 5, 10)


def ikarus_virus() -> Event:
    # Format nachgebildet – echte Probe erforderlich (⚠ zu verifizieren)
    return Event(
        "ikarus-sm", "IKARUS", f'virus_found host="{rnd(INTERNAL)}" user="{rnd(USERS)}" '
        f'file="C:\\Users\\{rnd(USERS)}\\Downloads\\invoice.pdf.exe" virus="Trojan.Win32.Agent" action="quarantined"', 2
    )


def arp_garp() -> Event:
    return Event("netsim", "arpwatch", f"changed ethernet address {rnd(INTERNAL)} {rnd(MACS)} (old {rnd(MACS)})", 4)


SOURCES: dict[str, Callable[[], Event]] = {
    "fortigate-traffic": fortigate_traffic,
    "fortigate-ips": fortigate_ips,
    "fortigate-admin": fortigate_admin,
    "fortigate-vpn": fortigate_vpn,
    "arubaos-link": arubaos_link,
    "arubaos-auth": arubaos_auth,
    "fs-link": fs_link,
    "linux-sshd": linux_sshd,
    "linux-sudo": linux_sudo,
    "ikarus-virus": ikarus_virus,
    "arp-change": arp_garp,
}

# Gewichtung bei --source all (Traffic dominiert wie in realen Umgebungen)
WEIGHTS = {"fortigate-traffic": 20, "linux-sshd": 3, "arubaos-link": 2}


# ---------------------------------------------------------------------------
# Formatierung
# ---------------------------------------------------------------------------
def format_rfc5424(ev: Event) -> str:
    pri = ev.facility * 8 + ev.severity
    ts = now().isoformat(timespec="milliseconds")
    return f"<{pri}>1 {ts} {ev.host} {ev.app or '-'} - - - {ev.msg}"


def format_rfc3164(ev: Event) -> str:
    pri = ev.facility * 8 + ev.severity
    t = now()
    tag = f"{ev.app}: " if ev.app else ""
    return f"<{pri}>{t:%b} {t.day:2d} {t:%H:%M:%S} {ev.host} {tag}{ev.msg}"


def format_event(ev: Event, fmt: str) -> str:
    # FortiGate sendet im Default-Format ohne App-Tag (RFC 3164-ähnlich)
    return format_rfc5424(ev) if fmt == "5424" else format_rfc3164(ev)


# ---------------------------------------------------------------------------
# Versand
# ---------------------------------------------------------------------------
class Sender:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.sock: socket.socket | None = None
        if args.stdout:
            return
        if args.proto == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raw = socket.create_connection((args.target, args.port), timeout=10)
            if args.proto == "tls":
                ctx = ssl.create_default_context(cafile=args.ca) if args.ca else ssl.create_default_context()
                if args.insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=args.target)
            self.sock = raw

    def send(self, line: str) -> None:
        if self.args.stdout:
            print(line)
            return
        data = line.encode("utf-8")
        assert self.sock is not None
        if self.args.proto == "udp":
            self.sock.sendto(data, (self.args.target, self.args.port))
        elif self.args.framing == "octet":
            self.sock.sendall(f"{len(data)} ".encode() + data)
        else:
            self.sock.sendall(data + b"\n")

    def close(self) -> None:
        if self.sock:
            self.sock.close()


def pick_source(names: list[str]) -> Callable[[], Event]:
    weights = [WEIGHTS.get(n, 1) for n in names]
    return SOURCES[random.choices(names, weights=weights)[0]]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--list", action="store_true", help="verfügbare Quellen anzeigen")
    p.add_argument("--source", default="all", help="Quelle(n), kommagetrennt, oder 'all'")
    p.add_argument("--target", default="127.0.0.1", help="Ziel-Host")
    p.add_argument("--port", type=int, default=None, help="Ziel-Port (Standard: 514, TLS 6514)")
    p.add_argument("--proto", choices=["udp", "tcp", "tls"], default="udp")
    p.add_argument("--framing", choices=["newline", "octet"], default="newline", help="TCP/TLS-Framing")
    p.add_argument("--format", choices=["3164", "5424"], default="3164")
    p.add_argument("--ca", help="CA-Datei für TLS")
    p.add_argument("--insecure", action="store_true", help="TLS-Zertifikat nicht prüfen (nur Labor)")
    p.add_argument("--eps", type=float, default=5.0, help="Ereignisse pro Sekunde")
    p.add_argument("--count", type=int, default=0, help="Anzahl (0 = unbegrenzt bzw. --duration)")
    p.add_argument("--duration", type=float, default=0, help="Dauer in Sekunden (0 = unbegrenzt)")
    p.add_argument("--seed", type=int, help="Zufallsstartwert (reproduzierbar)")
    p.add_argument("--stdout", action="store_true", help="nur ausgeben, nicht senden")
    args = p.parse_args(argv)

    if args.list:
        for name in SOURCES:
            print(name)
        return 0
    if args.seed is not None:
        random.seed(args.seed)
    if args.port is None:
        args.port = 6514 if args.proto == "tls" else 514

    names = list(SOURCES) if args.source == "all" else [s.strip() for s in args.source.split(",")]
    unknown = [n for n in names if n not in SOURCES]
    if unknown:
        p.error(f"unbekannte Quelle(n): {', '.join(unknown)} – siehe --list")

    sender = Sender(args)
    interval = 1.0 / args.eps if args.eps > 0 else 0
    start = time.monotonic()
    sent = 0
    try:
        while True:
            if args.count and sent >= args.count:
                break
            if args.duration and time.monotonic() - start >= args.duration:
                break
            sender.send(format_event(pick_source(names)(), args.format))
            sent += 1
            if interval and not args.stdout:
                next_at = start + sent * interval
                time.sleep(max(0.0, next_at - time.monotonic()))
    except KeyboardInterrupt:
        pass
    finally:
        sender.close()
    if not args.stdout:
        rate = sent / max(time.monotonic() - start, 1e-6)
        print(f"{sent} Ereignisse gesendet ({rate:.1f} EPS)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
