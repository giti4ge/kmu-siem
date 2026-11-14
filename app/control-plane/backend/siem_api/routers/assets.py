"""Asset-Center: Endgeräte (MAC) aus den Asset-Ereignissen der Switch-FDB, mit erstmals/zuletzt gesehen."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status

from ..deps import Ctx, error, require
from ..opensearch import OpenSearchUnavailable
from .logs import client_for

router = APIRouter(tags=["assets"], prefix="/api/assets")

MAX_ASSETS = 5000


def build_query(days: int) -> dict[str, Any]:
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                                      {"term": {"event.dataset": "asset.mac"}}]}},
        "aggs": {"mac": {
            "terms": {"field": "source.mac", "size": MAX_ASSETS},
            "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                     "latest": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                             "_source": ["observer.name", "observer.ip",
                                                         "observer.ingress.interface.name", "network.vlan.id"]}}}}},
    }


def build_ip_query(days: int) -> dict[str, Any]:
    """Letzte IP-/Hostname-Zuordnung je MAC aus FortiGate-ARP/DHCP."""
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                                      {"terms": {"event.dataset": ["fortigate.arp", "fortigate.dhcp"]}}]}},
        "aggs": {"mac": {
            "terms": {"field": "source.mac", "size": MAX_ASSETS},
            "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                     "latest": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                             "_source": ["source.ip", "host.hostname",
                                                         "observer.ingress.interface.name"]}}}}},
    }


def merge_ips(assets: list[dict[str, Any]], resp: dict[str, Any]) -> list[dict[str, Any]]:
    """IP/Hostname ergänzen; MACs, die nur die Firewall kennt, werden als eigene Einträge aufgenommen."""
    by_mac = {a["mac"]: a for a in assets}
    for b in resp.get("aggregations", {}).get("mac", {}).get("buckets", []):
        hits = b.get("latest", {}).get("hits", {}).get("hits", [])
        src = hits[0].get("_source", {}) if hits else {}
        a = by_mac.get(b.get("key"))
        if a is None:
            a = {"mac": b.get("key"), "switch": None, "switch_ip": None, "port": None, "vlan": None,
                 "first_seen": b.get("first", {}).get("value_as_string"),
                 "last_seen": b.get("last", {}).get("value_as_string"), "events": 0}
            assets.append(a)
            by_mac[a["mac"]] = a
        else:
            first, last = b.get("first", {}).get("value_as_string"), b.get("last", {}).get("value_as_string")
            a["first_seen"] = min(filter(None, [a["first_seen"], first]), default=None)
            a["last_seen"] = max(filter(None, [a["last_seen"], last]), default=None)
        a["ip"] = src.get("source", {}).get("ip")
        a["hostname"] = src.get("host", {}).get("hostname")
        a["interface"] = src.get("observer", {}).get("ingress", {}).get("interface", {}).get("name")
    for a in assets:
        a.setdefault("ip", None)
        a.setdefault("hostname", None)
        a.setdefault("interface", None)
    return sorted(assets, key=lambda a: str(a["last_seen"] or ""), reverse=True)


def parse(resp: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for b in resp.get("aggregations", {}).get("mac", {}).get("buckets", []):
        hits = b.get("latest", {}).get("hits", {}).get("hits", [])
        src = hits[0].get("_source", {}) if hits else {}
        obs = src.get("observer", {})
        out.append({
            "mac": b.get("key"), "switch": obs.get("name") or obs.get("ip"), "switch_ip": obs.get("ip"),
            "port": obs.get("ingress", {}).get("interface", {}).get("name"),
            "vlan": src.get("network", {}).get("vlan", {}).get("id"),
            "first_seen": b.get("first", {}).get("value_as_string"),
            "last_seen": b.get("last", {}).get("value_as_string"), "events": b.get("doc_count", 0),
        })
    return sorted(out, key=lambda a: str(a["last_seen"] or ""), reverse=True)


@router.get("")
def list_assets(request: Request, days: int = Query(30, ge=1, le=365),
                ctx: Ctx = Depends(require("assets:read"))) -> dict:
    try:
        c = client_for(request)
        assets = parse(c.search("siem-asset-*", build_query(days)))
        assets = merge_ips(assets, c.search("siem-asset-*", build_ip_query(days)))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    return {"days": days, "assets": assets, "truncated": len(assets) >= MAX_ASSETS}
