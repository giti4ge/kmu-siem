"""Geräteprofile für den SNMP-Poller (Spec 4.6): zusätzliche Werte je Gerätetyp, Hardwarezustand, LLDP-Nachbarn.

Ein Profil nennt Skalar-OIDs mit einer Bewertung (``ok``-Werte, ``warn``-Werte). Abweichungen erzeugen ein
Ereignis ``snmp.hardware`` (Aktion ``hardware-warning``/``hardware-critical``/``hardware-ok``), das die Alert-Regeln und
das Dashboard nutzen. Eigene OIDs aus importierten MIBs (siehe mibs.py) laufen als Profil ``custom`` ohne Bewertung.
"""

from __future__ import annotations

from typing import Any

# Dell iDRAC: 3 ok, 4 nonCritical, 5 critical, 6 nonRecoverable; Synology: 1 normal, 2 failed
_DELL = {"ok": {"3", "2"}, "warn": {"4"}, "crit": {"5", "6"}}
PROFILES: dict[str, dict[str, Any]] = {
    "generic": {"label": "Allgemein (IF-MIB, FDB, LLDP)", "scalars": {}},
    "synology": {"label": "Synology NAS", "scalars": {
        "system_status": {"oid": "1.3.6.1.4.1.6574.1.1.0", "ok": {"1"}, "crit": {"2"}},
        "temperature_c": {"oid": "1.3.6.1.4.1.6574.1.2.0", "max": 70},
        "power_status": {"oid": "1.3.6.1.4.1.6574.1.3.0", "ok": {"1"}, "crit": {"2"}},
        "fan_status": {"oid": "1.3.6.1.4.1.6574.1.4.1.0", "ok": {"1"}, "crit": {"2"}},
    }},
    "idrac": {"label": "Dell iDRAC", "scalars": {
        "global_status": {"oid": "1.3.6.1.4.1.674.10892.5.2.1.0", **_DELL},
        "storage_status": {"oid": "1.3.6.1.4.1.674.10892.5.2.3.0", **_DELL},
    }},
    "aruba": {"label": "ArubaOS-Switch (HP)", "scalars": {
        "cpu_percent": {"oid": "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0", "max": 90},
    }},
    "custom": {"label": "Eigene OIDs (aus MIB-Import)", "scalars": {}},
}
LLDP_REM = {
    "chassis": "1.0.8802.1.1.2.1.4.1.1.5", "port_id": "1.0.8802.1.1.2.1.4.1.1.7",
    "port_desc": "1.0.8802.1.1.2.1.4.1.1.8", "sys_name": "1.0.8802.1.1.2.1.4.1.1.9",
}
MAX_NEIGHBORS = 256


def judge(spec: dict[str, Any], raw: Any) -> str:
    """ok | warn | critical | info (ohne Bewertung)."""
    v = str(raw).strip()
    if "max" in spec:
        try:
            return "warn" if float(v) > spec["max"] else "ok"
        except ValueError:
            return "info"
    if v in spec.get("crit", ()):
        return "critical"
    if v in spec.get("warn", ()):
        return "warn"
    if v in spec.get("ok", ()):
        return "ok"
    return "warn" if spec.get("ok") else "info"


def scalars_for(profile: str, custom: list[dict[str, str]] | None) -> dict[str, dict[str, Any]]:
    out = dict(PROFILES.get(profile, PROFILES["generic"])["scalars"])
    for c in custom or []:
        out[f"custom_{c['name']}"[:48]] = {"oid": c["oid"]}
    return out


async def collect_profile(session: Any, profile: str, custom: list[dict[str, str]] | None) -> dict[str, dict[str, Any]]:
    """Werte je Profil-Skalar mit Bewertung; nicht lesbare Werte entfallen."""
    out: dict[str, dict[str, Any]] = {}
    for key, spec in scalars_for(profile, custom).items():
        try:
            got = await session.get([spec["oid"]])
        except Exception:  # noqa: BLE001, S112 – Gerät kennt den OID nicht (andere Firmware)
            continue
        raw = next(iter(got.values()), None)
        if raw is None or str(raw).startswith(("No Such", "noSuch", "No such")):
            continue
        out[key] = {"value": str(raw), "state": judge(spec, raw)}
    return out


async def collect_lldp(session: Any) -> list[dict[str, str]]:
    """LLDP-Nachbarn (lldpRemTable); Index = timeMark.localPort.index."""
    cols = {k: await session.walk(oid) for k, oid in LLDP_REM.items()}
    out = []
    for suffix in sorted(cols["sys_name"].keys() | cols["port_id"].keys())[:MAX_NEIGHBORS]:
        parts = suffix.split(".")
        if len(parts) < 3:
            continue
        out.append({"local_port": parts[1], "remote_name": str(cols["sys_name"].get(suffix, "")),
                    "remote_port": str(cols["port_id"].get(suffix) or cols["port_desc"].get(suffix, "")),
                    "remote_chassis": str(cols["chassis"].get(suffix, ""))})
    return out
