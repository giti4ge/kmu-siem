"""MITRE ATT&CK: Katalog der relevanten Techniken, Zuordnung der Alarmregeln und Abdeckungsmatrix (Enterprise-Matrix).

Berücksichtigt werden die zwölf Taktiken, die sich aus Logdaten erkennen lassen (Reconnaissance und Resource
Development finden außerhalb des eigenen Netzes statt). Techniken ohne Regel erscheinen als Lücke.
"""

from __future__ import annotations

from typing import Any

TACTICS = ("initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
           "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
           "exfiltration", "impact")

# id -> (Name, Taktiken)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1566": ("Phishing", ("initial-access",)),
    "T1078": ("Valid Accounts", ("initial-access", "persistence", "privilege-escalation", "defense-evasion")),
    "T1059": ("Command and Scripting Interpreter", ("execution",)),
    "T1204": ("User Execution", ("execution",)),
    "T1053": ("Scheduled Task/Job", ("execution", "persistence", "privilege-escalation")),
    "T1098": ("Account Manipulation", ("persistence",)),
    "T1136": ("Create Account", ("persistence",)),
    "T1543.003": ("Create or Modify System Process: Windows Service", ("persistence", "privilege-escalation")),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ("privilege-escalation", "defense-evasion")),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ("defense-evasion",)),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ("defense-evasion",)),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ("defense-evasion",)),
    "T1110": ("Brute Force", ("credential-access",)),
    "T1003": ("OS Credential Dumping", ("credential-access",)),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", ("credential-access", "collection")),
    "T1046": ("Network Service Discovery", ("discovery",)),
    "T1021": ("Remote Services", ("lateral-movement",)),
    "T1005": ("Data from Local System", ("collection",)),
    "T1071": ("Application Layer Protocol", ("command-and-control",)),
    "T1048": ("Exfiltration Over Alternative Protocol", ("exfiltration",)),
    "T1486": ("Data Encrypted for Impact", ("impact",)),
    "T1499": ("Endpoint Denial of Service", ("impact",)),
}


def url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def info(ids: tuple[str, ...] | list[str]) -> list[dict[str, Any]]:
    """Technik-ID → Name, Taktiken und Link (Stufe 1: Zuordnung je Regel)."""
    return [{"id": i, "name": TECHNIQUES.get(i, (i, ()))[0], "tactics": list(TECHNIQUES.get(i, (i, ()))[1]),
             "url": url(i)} for i in ids]


def matrix(rules: list[Any]) -> dict[str, Any]:
    """Stufe 2: Abdeckungsmatrix. Status je Technik: covered (mind. eine aktive Regel), disabled, gap."""
    by_tech: dict[str, list[dict[str, Any]]] = {}
    for r in rules:
        for t in r.mitre:
            by_tech.setdefault(t, []).append({"id": r.id, "name": r.name, "enabled": r.enabled})
    techs = dict(TECHNIQUES)
    for t in by_tech:
        techs.setdefault(t, (t, ()))
    cols: list[dict[str, Any]] = []
    for tac in TACTICS:
        items = []
        for tid, (name, tacs) in sorted(techs.items()):
            if tac not in tacs:
                continue
            rs = by_tech.get(tid, [])
            status = "covered" if any(x["enabled"] for x in rs) else "disabled" if rs else "gap"
            items.append({"id": tid, "name": name, "url": url(tid), "status": status, "rules": rs})
        cols.append({"tactic": tac, "techniques": items})
    flat = {i["id"]: i["status"] for c in cols for i in c["techniques"]}
    total = len(flat)
    covered = sum(1 for s in flat.values() if s == "covered")
    return {"tactics": cols, "summary": {"techniques": total, "covered": covered, "disabled": sum(1 for s in flat.values() if s == "disabled"),
                                         "gaps": total - covered - sum(1 for s in flat.values() if s == "disabled")}}
