"""Port-Matrix: letzter Status je SNMP-Gerät (Schnittstellen aus dem jüngsten ``snmp.device``-Ereignis)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, status

from ..deps import Ctx, error, require
from ..opensearch import OpenSearchUnavailable
from .logs import client_for

router = APIRouter(tags=["switches"], prefix="/api/switches")

STALE_SECONDS = 300  # > 5 Zyklen ohne Status-Ereignis


def build_query(hours: int = 24, dataset: str = "snmp.device", action: str = "poll") -> dict[str, Any]:
    return {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            {"term": {"event.dataset": dataset}}, {"term": {"event.action": action}}]}},
        "aggs": {"dev": {"terms": {"field": "observer.ip", "size": 500},
                         "aggs": {"last": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}]}}}}},
    }


def parse_fdb(resp: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for b in resp.get("aggregations", {}).get("dev", {}).get("buckets", []):
        hits = b.get("last", {}).get("hits", {}).get("hits", [])
        if hits:
            out[str(b.get("key"))] = hits[0].get("_source", {}).get("snmp", {}).get("fdb", {}).get("entries", [])
    return out


def attach_fdb(devices: list[dict[str, Any]], fdb: dict[str, list[dict[str, Any]]]) -> None:
    """MAC-Anzahl je Port (Uplinks erkennt man an vielen MACs) und MAC-Liste je Gerät."""
    for d in devices:
        entries = fdb.get(str(d["ip"]), [])
        counts: dict[int, int] = {}
        for e in entries:
            counts[e.get("if_index", 0)] = counts.get(e.get("if_index", 0), 0) + 1
        for i in d["interfaces"]:
            i["macs"] = counts.get(i.get("index"), 0)
        d["fdb"] = entries


def parse(resp: dict[str, Any], now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(UTC)
    devices = []
    for b in resp.get("aggregations", {}).get("dev", {}).get("buckets", []):
        hits = b.get("last", {}).get("hits", {}).get("hits", [])
        if not hits:
            continue
        src = hits[0].get("_source", {})
        snmp = src.get("snmp", {})
        ts = src.get("@timestamp", "")
        try:
            age = (now - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds()
        except ValueError:
            age = float("inf")
        devices.append({
            "ip": b.get("key"), "name": src.get("observer", {}).get("name") or b.get("key"),
            "sys_descr": snmp.get("sys_descr", ""), "uptime_ticks": snmp.get("uptime_ticks", 0), "last_seen": ts,
            "stale": age > STALE_SECONDS, "ports_total": snmp.get("ports_total", 0),
            "ports_up": snmp.get("ports_up", 0), "interfaces": snmp.get("interfaces", []),
        })
    return sorted(devices, key=lambda d: str(d["name"]).lower())


@router.get("")
def list_devices(request: Request, ctx: Ctx = Depends(require("switches:read"))) -> dict:
    try:
        c = client_for(request)
        devices = parse(c.search("siem-network-*,siem-infra-*", build_query()))
        # FDB wird nur alle 5 min erhoben: eigene Abfrage des jüngsten FDB-Ereignisses
        fdb = parse_fdb(c.search("siem-network-*,siem-infra-*", build_query(24, "snmp.fdb", "fdb")))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    attach_fdb(devices, fdb)
    return {"devices": devices}
