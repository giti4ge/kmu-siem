"""Alert-Engine (Phase 5.1): Regeln → OpenSearch-Abfragen → Alarme in ``siem-alerts-*``.

Regeltypen in einem Modell: Filter (Feld → erlaubte Werte), optional Gruppierung (``group_by``), Mindestanzahl
(``threshold``) im Zeitfenster und optional Mindestanzahl verschiedener Werte (``distinct``, z. B. Portscan).
Alarme haben eine feste ID je Regel, Gruppe und Tag: Wiederholungen aktualisieren Zähler und Zeit, ein
bestätigter/geschlossener Alarm wird nicht wieder geöffnet; nur ein neu angelegter Alarm löst eine Benachrichtigung aus.
Regel-Einstellungen (an/aus, Schweregrad, Schwellwert) liegen in ``rules.json`` im Secrets-Verzeichnis.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import mitre
from .opensearch import OpenSearchClient, OpenSearchUnavailable

INTERVAL_SECONDS = 60
SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "acknowledged", "closed")
MAX_GROUPS = 50


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    description: str
    filters: dict[str, list[str]]
    group_by: str | None = None
    threshold: int = 1
    window_minutes: int = 5
    distinct: tuple[str, int] | None = None  # (Feld, Mindestanzahl verschiedener Werte)
    mitre: tuple[str, ...] = ()
    enabled: bool = True
    category: str = "windows"  # nur zur Gruppierung im UI
    extra: dict[str, Any] = field(default_factory=dict, compare=False)


def _r(id_: str, name: str, sev: str, desc: str, filters: dict[str, list[str]], **kw: Any) -> Rule:
    return Rule(id_, name, sev, desc, filters, **kw)


BUILTIN_RULES: tuple[Rule, ...] = (
    _r("win-bruteforce-ip", "Windows: viele fehlgeschlagene Anmeldungen von einer Quelle", "high",
       "Mindestens 10 fehlgeschlagene Anmeldungen (4625) von derselben Quelladresse in 5 Minuten.",
       {"winlog.event_id": ["4625"]}, group_by="source.ip", threshold=10, mitre=("T1110",)),
    _r("win-bruteforce-user", "Windows: viele fehlgeschlagene Anmeldungen für ein Konto", "high",
       "Mindestens 10 fehlgeschlagene Anmeldungen (4625) für dasselbe Konto in 5 Minuten.",
       {"winlog.event_id": ["4625"]}, group_by="user.name", threshold=10, mitre=("T1110",)),
    _r("win-log-cleared", "Windows: Ereignisprotokoll gelöscht", "critical",
       "Das Sicherheits- oder Systemprotokoll wurde gelöscht (1102/104) – typisch beim Verwischen von Spuren.",
       {"event.action": ["audit-log-cleared", "log-cleared"]}, group_by="host.name", mitre=("T1070.001",)),
    _r("win-privileged-group", "Windows: Mitglied zu Gruppe hinzugefügt", "high",
       "Ein Konto wurde einer Sicherheitsgruppe hinzugefügt (4728/4732/4756).",
       {"event.action": ["group-member-added"]}, group_by="host.name", mitre=("T1098",)),
    _r("win-service-installed", "Windows: neuer Dienst installiert", "medium",
       "Ein neuer Dienst wurde installiert (7045) – häufig bei Schadsoftware und Fernwartungswerkzeugen.",
       {"event.action": ["service-installed"]}, group_by="host.name", mitre=("T1543.003",)),
    _r("win-malware", "Windows Defender: Schadsoftware erkannt", "high",
       "Defender hat Schadsoftware erkannt oder die Bereinigung ist fehlgeschlagen.",
       {"event.action": ["malware-detected", "malware-action-failed"]}, group_by="host.name", mitre=("T1204",)),
    _r("win-defender-off", "Windows Defender: Echtzeitschutz deaktiviert", "high",
       "Der Echtzeitschutz wurde abgeschaltet (5001).",
       {"event.action": ["realtime-protection-disabled"]}, group_by="host.name", mitre=("T1562.001",)),
    _r("fw-ips-high", "Firewall: IPS-/UTM-Treffer mit hohem Schweregrad", "high",
       "Die FortiGate hat einen Angriff mit hohem oder kritischem Schweregrad erkannt.",
       {"event.dataset": ["fortigate.utm"], "fortinet.severity": ["high", "critical"]}, group_by="source.ip",
       category="firewall", mitre=("T1190",)),
    _r("fw-portscan", "Firewall: Portscan", "medium",
       "Eine Quelle versucht innerhalb von 5 Minuten mindestens 30 verschiedene Zielports (abgelehnt).",
       {"event.dataset": ["fortigate.traffic"], "event.outcome": ["failure"]}, group_by="source.ip",
       distinct=("destination.port", 30), category="firewall", mitre=("T1046",)),
    _r("fw-deny-flood", "Firewall: sehr viele abgelehnte Verbindungen", "low",
       "Mehr als 500 abgelehnte Verbindungen einer Quelle in 5 Minuten.",
       {"event.dataset": ["fortigate.traffic"], "event.outcome": ["failure"]}, group_by="source.ip",
       threshold=500, category="firewall", mitre=("T1499",)),
    _r("fw-config-change", "Firewall: Konfigurationsänderung", "medium",
       "An der FortiGate wurde die Konfiguration geändert.",
       {"event.action": ["config-change"]}, group_by="observer.ip", category="firewall", mitre=("T1562.004",)),
    _r("asset-ip-mac-changed", "Netzwerk: IP-Adresse wechselt die MAC-Adresse (ARP-Spoofing?)", "high",
       "Eine IP-Adresse gehört plötzlich zu einer anderen MAC-Adresse.",
       {"event.action": ["ip-mac-changed"]}, group_by="source.ip", category="network", mitre=("T1557.002",)),
    _r("net-login-failed", "Switch: viele fehlgeschlagene Anmeldungen", "medium",
       "Mindestens 10 fehlgeschlagene Anmeldungen an einem Netzwerkgerät in 5 Minuten.",
       {"event.action": ["login-failed"]}, group_by="observer.ip", threshold=10, category="network",
       mitre=("T1110",)),
    _r("linux-ssh-bruteforce", "Linux: viele fehlgeschlagene SSH-Anmeldungen", "high",
       "Mindestens 10 fehlgeschlagene SSH-Anmeldungen von einer Quelle in 5 Minuten.",
       {"event.action": ["ssh-login-failed"]}, group_by="source.ip", threshold=10, category="linux",
       mitre=("T1110",)),
    _r("linux-sudo-failed", "Linux: wiederholt fehlgeschlagenes sudo", "medium",
       "Mindestens 5 fehlgeschlagene sudo-Versuche eines Kontos in 10 Minuten.",
       {"event.action": ["sudo-failed"]}, group_by="user.name", threshold=5, window_minutes=10, category="linux",
       mitre=("T1548.003",)),
)


# ---------------------------------------------------------------- Einstellungen

class RuleStore:
    """Rückgabe der Regeln mit gespeicherten Überschreibungen (enabled, severity, threshold)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def rules(self) -> list[Rule]:
        over = self._load()
        out = []
        for r in BUILTIN_RULES:
            o = over.get(r.id, {})
            kw: dict[str, Any] = {}
            if isinstance(o.get("enabled"), bool):
                kw["enabled"] = o["enabled"]
            if o.get("severity") in SEVERITIES:
                kw["severity"] = o["severity"]
            if isinstance(o.get("threshold"), int) and 1 <= o["threshold"] <= 100000:
                kw["threshold"] = o["threshold"]
            out.append(replace(r, **kw))
        return out

    def update(self, rule_id: str, changes: dict[str, Any]) -> None:
        with self.lock:
            data = self._load()
            data.setdefault(rule_id, {}).update(changes)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)


def rule_view(r: Rule) -> dict[str, Any]:
    d = asdict(r)
    d.pop("extra", None)
    d["distinct"] = list(r.distinct) if r.distinct else None
    d["mitre"] = list(r.mitre)
    d["mitre_info"] = mitre.info(r.mitre)
    return d


# ---------------------------------------------------------------- Abfrage und Auswertung

def build_query(rule: Rule) -> dict[str, Any]:
    flt: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{rule.window_minutes}m"}}}]
    flt += [{"terms": {k: v}} for k, v in rule.filters.items()]
    body: dict[str, Any] = {"size": 3, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": flt}},
                            "_source": ["@timestamp", "host.name", "user.name", "source.ip", "observer.ip",
                                        "event.action", "message"]}
    if rule.group_by:
        sub: dict[str, Any] = {"last": {"max": {"field": "@timestamp"}},
                               "sample": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                                       "_source": ["event.original", "message", "host.name"]}}}
        if rule.distinct:
            sub["distinct"] = {"cardinality": {"field": rule.distinct[0]}}
        body["size"] = 0
        body["aggs"] = {"g": {"terms": {"field": rule.group_by, "size": MAX_GROUPS, "min_doc_count": rule.threshold},
                              "aggs": sub}}
    return body


def evaluate(rule: Rule, resp: dict[str, Any]) -> list[dict[str, Any]]:
    """Trefferliste → Alarmkandidaten (Gruppe, Anzahl, letzter Zeitpunkt, Beispiel)."""
    out: list[dict[str, Any]] = []
    if rule.group_by:
        for b in resp.get("aggregations", {}).get("g", {}).get("buckets", []):
            if b.get("doc_count", 0) < rule.threshold:
                continue
            if rule.distinct and b.get("distinct", {}).get("value", 0) < rule.distinct[1]:
                continue
            hit = (b.get("sample", {}).get("hits", {}).get("hits") or [{}])[0].get("_source", {})
            out.append({"group": str(b["key"]), "count": b["doc_count"], "last": b.get("last", {}).get("value_as_string"),
                        "sample": str(hit.get("event", {}).get("original") or hit.get("message") or "")[:300],
                        "distinct": b.get("distinct", {}).get("value")})
    else:
        total = resp.get("hits", {}).get("total", {})
        count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        if count >= rule.threshold:
            hit = (resp.get("hits", {}).get("hits") or [{}])[0].get("_source", {})
            out.append({"group": "", "count": count, "last": hit.get("@timestamp"),
                        "sample": str(hit.get("message") or "")[:300], "distinct": None})
    return out


def alert_id(rule_id: str, group: str, day: str) -> str:
    return hashlib.sha256(f"{rule_id}|{group}|{day}".encode()).hexdigest()[:32]


def summary(rule: Rule, c: dict[str, Any]) -> str:
    who = f" ({rule.group_by}: {c['group']})" if rule.group_by else ""
    return f"{rule.name}{who} – {c['count']} Ereignisse in {rule.window_minutes} min"


def upsert_alert(client: OpenSearchClient, rule: Rule, c: dict[str, Any], now: datetime) -> bool:
    """Legt den Alarm an oder aktualisiert Zähler/Zeit; Rückgabe True nur bei neu angelegtem Alarm."""
    day = now.strftime("%Y.%m.%d")
    aid = alert_id(rule.id, c["group"], day)
    ts = now.astimezone(UTC).isoformat(timespec="seconds")
    base = {"count": c["count"], "last_seen": c["last"] or ts, "summary": summary(rule, c), "sample": c["sample"]}
    doc = {
        "@timestamp": ts, "siem": {"category": "alerts"}, "event": {"kind": "alert", "dataset": "siem.alert"},
        "rule": {"id": rule.id, "name": rule.name},
        "alert": {**base, "id": aid, "severity": rule.severity, "status": "open", "group": c["group"],
                  "group_by": rule.group_by or "", "first_seen": ts, "mitre": list(rule.mitre),
                  "description": rule.description},
    }
    resp = client.request("POST", f"/siem-alerts-{day}/_update/{aid}?refresh=true",
                          {"doc": {"alert": base}, "upsert": doc})
    return bool(resp) and resp.get("result") == "created"


def run_cycle(client: OpenSearchClient, store: RuleStore, now: datetime,
              notify: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    stats = {"rules": 0, "matches": 0, "created": 0, "errors": 0}
    for rule in store.rules():
        if not rule.enabled:
            continue
        stats["rules"] += 1
        try:
            resp = client.search("siem-*", build_query(rule))
            for c in evaluate(rule, resp):
                stats["matches"] += 1
                if upsert_alert(client, rule, c, now):
                    stats["created"] += 1
                    if notify:
                        notify({"rule": rule_view(rule), "group": c["group"], "count": c["count"],
                                "summary": summary(rule, c), "sample": c["sample"], "severity": rule.severity})
        except OpenSearchUnavailable:
            stats["errors"] += 1
    return stats


class Engine(threading.Thread):
    def __init__(self, client: OpenSearchClient, store: RuleStore,
                 notify: Callable[[dict[str, Any]], None] | None = None) -> None:
        super().__init__(daemon=True, name="alert-engine")
        self.client, self.store, self.notify = client, store, notify
        self.stop = threading.Event()
        self.last: dict[str, Any] = {}

    def run(self) -> None:
        while not self.stop.wait(INTERVAL_SECONDS):
            self.last = run_cycle(self.client, self.store, datetime.now().astimezone(), self.notify) | {
                "at": datetime.now(UTC).isoformat(timespec="seconds")}
