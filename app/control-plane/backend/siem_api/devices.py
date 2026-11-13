"""Geräteliste: Validierung und Erzeugung von devices.csv für Vector (Quell-IP → Gerätetyp)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

# Muss den Typen in app/vector/vector.yaml (transforms.route_device) entsprechen
DEVICE_TYPES = ("fortigate", "arubaos", "instant_on", "fs_s3900", "linux")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


class DeviceError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise DeviceError("device_invalid_ip") from exc


def validate(ip: str, name: str, type_: str) -> tuple[str, str, str]:
    name = name.strip()
    if not _NAME.match(name):
        raise DeviceError("device_invalid_name")
    if type_ not in DEVICE_TYPES:
        raise DeviceError("device_invalid_type")
    return normalize_ip(ip), name, type_


def render_csv(devices: list[tuple[str, str]]) -> str:
    """(IP, Typ)-Paare als CSV; die Werte sind validiert (keine Trennzeichen möglich)."""
    lines = ["ip,type"] + [f"{ip},{typ}" for ip, typ in sorted(devices)]
    return "\n".join(lines) + "\n"


def write_csv(directory: Path, devices: list[tuple[str, str]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "devices.csv"
    tmp = directory / "devices.csv.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render_csv(devices))
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)
