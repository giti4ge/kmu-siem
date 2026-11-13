"""Ereignis-Übersichten aus OpenSearch: nicht erkannte Quellen („Unparsed“) und Volumen je Kategorie."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status

from ..deps import Ctx, error, require, state
from ..opensearch import OpenSearchClient, OpenSearchUnavailable

router = APIRouter(tags=["logs"], prefix="/api/logs")

CATEGORIES = ("firewall", "windows", "linux", "network", "edr", "av", "asset", "infra", "alerts", "audit",
              "system", "unparsed")


def client_for(request: Request) -> OpenSearchClient:
    st = state(request)
    return OpenSearchClient(st.settings.opensearch_url, st.settings.secrets_dir)


def unparsed_query(hours: int) -> dict[str, Any]:
    """Gruppiert nicht erkannte Ereignisse nach Absender und Programm, mit Beispielen."""
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"sources": {
            "multi_terms": {"terms": [{"field": "observer.ip"}, {"field": "process.name", "missing": ""}], "size": 100},
            "aggs": {
                "last": {"max": {"field": "@timestamp"}},
                "samples": {"top_hits": {"size": 3, "sort": [{"@timestamp": "desc"}],
                                         "_source": ["event.original", "host.hostname", "@timestamp"]}},
            },
        }},
    }


def parse_unparsed(resp: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for b in resp.get("aggregations", {}).get("sources", {}).get("buckets", []):
        ip, prog = (list(b.get("key", [])) + ["", ""])[:2]
        samples = [h.get("_source", {}) for h in b.get("samples", {}).get("hits", {}).get("hits", [])]
        out.append({
            "ip": ip, "program": prog, "count": b.get("doc_count", 0),
            "last_seen": b.get("last", {}).get("value_as_string"),
            "hostname": next((s.get("host", {}).get("hostname") for s in samples if s.get("host")), None),
            "samples": [str(s.get("event", {}).get("original", ""))[:500] for s in samples],
        })
    return sorted(out, key=lambda r: -r["count"])


@router.get("/unparsed")
def unparsed(request: Request, hours: int = Query(24, ge=1, le=720),
             ctx: Ctx = Depends(require("logs:read"))) -> dict:
    try:
        resp = client_for(request).search("siem-unparsed-*", unparsed_query(hours))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    return {"hours": hours, "sources": parse_unparsed(resp)}


@router.get("/volume")
def volume(request: Request, hours: int = Query(24, ge=1, le=720),
           ctx: Ctx = Depends(require("logs:read"))) -> dict:
    body = {"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {"cat": {"terms": {"field": "siem.category", "size": 50}}}}
    try:
        resp = client_for(request).search("siem-*", body)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    counts = {b["key"]: b["doc_count"] for b in resp.get("aggregations", {}).get("cat", {}).get("buckets", [])}
    return {"hours": hours, "categories": {c: counts.get(c, 0) for c in CATEGORIES}}
