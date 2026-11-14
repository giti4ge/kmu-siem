"""Reports (Spec 4.10, vereinfacht): Zusammenfassung eines Zeitraums und CSV-Export der Alarme.

Die PDF-Ausgabe erfolgt über den Druckdialog des Browsers (Seite „Reports“); eine serverseitige PDF-Engine
(WeasyPrint, ADR-18) ist für eine spätere Version vorgesehen.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from .opensearch import OpenSearchClient

_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> str:
    """Entschärft Formelanfänge (CSV-Injection) und liefert Text."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(_FORMULA) else s


def alerts_csv(rows: list[dict[str, Any]]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["Zeit", "Schweregrad", "Status", "Regel", "Gruppe", "Anzahl", "Zusammenfassung", "MITRE"])
    for r in rows:
        w.writerow([csv_cell(x) for x in (r.get("time"), r.get("severity"), r.get("status"), r.get("rule"), r.get("group"),
                                          r.get("count"), r.get("summary"), ",".join(r.get("mitre") or []))])
    return out.getvalue()


def _buckets(resp: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [{"key": b["key"], "count": b["doc_count"]} for b in resp.get("aggregations", {}).get(name, {}).get("buckets", [])]


def summary(client: OpenSearchClient, days: int) -> dict[str, Any]:
    rng = {"range": {"@timestamp": {"gte": f"now-{days}d"}}}
    al = client.search("siem-alerts-*", {"size": 0, "query": rng, "aggs": {
        "sev": {"terms": {"field": "alert.severity", "size": 10}}, "st": {"terms": {"field": "alert.status", "size": 10}},
        "rule": {"terms": {"field": "rule.name", "size": 10}},
        "day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}}})
    vol = client.search("siem-*", {"size": 0, "query": rng, "aggs": {"c": {"terms": {"field": "siem.category", "size": 50}}}})
    blocked = client.search("siem-firewall-*", {"size": 0, "query": {"bool": {"filter": [rng, {"term": {"event.outcome": "failure"}}]}},
                                                "aggs": {"s": {"terms": {"field": "source.ip", "size": 10}}}})
    changes = client.search("siem-*", {"size": 0, "query": {"bool": {"filter": [rng, {"exists": {"field": "siem.change.operation"}}]}},
                                       "track_total_hits": True})
    total = changes.get("hits", {}).get("total", {})
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"), "days": days,
        "alerts_by_severity": _buckets(al, "sev"), "alerts_by_status": _buckets(al, "st"), "top_rules": _buckets(al, "rule"),
        "alerts_per_day": [{"key": b["key_as_string"][:10], "count": b["doc_count"]}
                           for b in al.get("aggregations", {}).get("day", {}).get("buckets", [])],
        "events_by_category": _buckets(vol, "c"), "top_blocked": _buckets(blocked, "s"),
        "changes": total.get("value", 0) if isinstance(total, dict) else int(total or 0),
    }
