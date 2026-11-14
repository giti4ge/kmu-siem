"""Threat-Dashboard (Spec 4.16): Ampel je Bereich, offene Alarme, Top-Quellen, Anmelde-Anomalien, Speicher."""

from __future__ import annotations

from typing import Any

from . import alerts as al
from .opensearch import OpenSearchClient, OpenSearchUnavailable

# Bereich → Regelkategorien (Regeln tragen ihre Kategorie, siehe alerts.Rule.category)
AREAS = {"perimeter": ("firewall",), "windows": ("windows",), "servers": ("linux",), "network": ("network",),
         "endpoints": ("edr", "av")}
_CATEGORY = {r.id: r.category for r in al.BUILTIN_RULES}
_ORDER = {"ok": 0, "info": 1, "warn": 2, "critical": 3}


def area_status(counts: dict[str, dict[str, int]]) -> dict[str, str]:
    """counts: Regelkategorie → {Schweregrad: offene Alarme}; Ergebnis: Bereich → ok | warn | critical."""
    out = {}
    for area, cats in AREAS.items():
        sev: dict[str, int] = {}
        for c in cats:
            for k, v in counts.get(c, {}).items():
                sev[k] = sev.get(k, 0) + v
        out[area] = "critical" if sev.get("critical") or sev.get("high") else "warn" if sev.get("medium") or sev.get("low") else "ok"
    return out


def _terms(resp: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [{"key": b["key"], "count": b["doc_count"]} for b in resp.get("aggregations", {}).get(name, {}).get("buckets", [])]


def build(client: OpenSearchClient, maintenance: dict[str, Any]) -> dict[str, Any]:
    day = {"range": {"@timestamp": {"gte": "now-24h"}}}
    res: dict[str, Any] = {"alerts": {"open": {}, "by_area": {}}, "areas": {}, "top_blocked": [], "failed_logons": [],
                           "failed_sources": [], "volume": {}, "unparsed_sources": 0, "disk": None, "errors": []}
    try:
        a = client.search("siem-alerts-*", {"size": 0, "query": {"bool": {"filter": [{"term": {"alert.status": "open"}}]}},
                                            "aggs": {"sev": {"terms": {"field": "alert.severity", "size": 10}},
                                                     "rule": {"terms": {"field": "rule.id", "size": 100}, "aggs": {
                                                         "sev": {"terms": {"field": "alert.severity", "size": 10}}}}}})
        res["alerts"]["open"] = {b["key"]: b["doc_count"] for b in a.get("aggregations", {}).get("sev", {}).get("buckets", [])}
        per_cat: dict[str, dict[str, int]] = {}
        for rb in a.get("aggregations", {}).get("rule", {}).get("buckets", []):
            cat = _CATEGORY.get(rb["key"], "other")
            for sb in rb["sev"]["buckets"]:
                per_cat.setdefault(cat, {})
                per_cat[cat][sb["key"]] = per_cat[cat].get(sb["key"], 0) + sb["doc_count"]
        res["alerts"]["by_area"] = per_cat
        res["areas"] = area_status(per_cat)
        v = client.search("siem-*", {"size": 0, "query": day, "aggs": {"c": {"terms": {"field": "siem.category", "size": 50}}}})
        res["volume"] = {r["key"]: r["count"] for r in _terms(v, "c")}
        res["top_blocked"] = _terms(client.search("siem-firewall-*", {"size": 0, "query": {"bool": {"filter": [
            day, {"term": {"event.outcome": "failure"}}]}}, "aggs": {"s": {"terms": {"field": "source.ip", "size": 10}}}}), "s")
        w = client.search("siem-windows-*", {"size": 0, "query": {"bool": {"filter": [day, {"term": {"winlog.event_id": "4625"}}]}},
                                             "aggs": {"u": {"terms": {"field": "user.name", "size": 5}},
                                                      "s": {"terms": {"field": "source.ip", "size": 5}}}})
        res["failed_logons"], res["failed_sources"] = _terms(w, "u"), _terms(w, "s")
        u = client.search("siem-unparsed-*", {"size": 0, "query": day, "aggs": {"n": {"cardinality": {"field": "observer.ip"}}}})
        res["unparsed_sources"] = u.get("aggregations", {}).get("n", {}).get("value", 0)
    except OpenSearchUnavailable as exc:
        res["errors"].append(str(exc)[:100])
    g = (maintenance.get("guard") or {}).get("detail")
    if isinstance(g, dict):
        res["disk"] = {"percent": g.get("percent"), "level": g.get("level")}
    return res
