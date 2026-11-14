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
        resp = client_for(request).search("siem-asset-*", build_query(days))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    assets = parse(resp)
    return {"days": days, "assets": assets, "truncated": len(assets) >= MAX_ASSETS}
