"""Ereignis-Übersichten aus OpenSearch: nicht erkannte Quellen („Unparsed“) und Volumen je Kategorie."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ..anonymizer import Pseudonymizer
from ..deps import Ctx, error, get_db, require, state
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


_SUGGEST = (  # (Gerätetyp, Programmnamen, Textmuster) – wie Auto-Detect in Vector, nur als Vorschlag
    ("linux", {"sshd", "sudo", "su", "systemd", "systemd-logind", "cron", "CRON", "auditd", "apt", "dpkg"}, ()),
    ("arubaos", {"ports", "FFI", "mgr", "stp", "lacp", "dhcp-snoop", "arp-prot"}, ()),
    ("fortigate", set(), ("devid=", "logid=")),
    ("synology", set(), ("FileStation", "WinFileService", "SMBFileService")),
    ("idrac", set(), ("MessageID=",)),
    ("unifi_controller", set(), ("UNIFIcategory=", "UNIFIevent=")),
)


def suggest_type(program: str, samples: list[str]) -> dict[str, Any] | None:
    """Gerätetyp-Vorschlag aus Programmname und Beispielzeilen (Freigabe bleibt Entscheidung des Administrators)."""
    text = " ".join(samples)
    for typ, progs, pats in _SUGGEST:
        hits = (program in progs) + sum(p in text for p in pats)
        if hits:
            return {"type": typ, "confidence": min(95, 60 + 20 * hits)}
    return None


def ignored(secrets_dir: Any) -> set[str]:
    try:
        return set(json.loads((secrets_dir / "unparsed-ignore.json").read_text("utf-8")))
    except (OSError, ValueError):
        return set()


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
        out[-1]["suggestion"] = suggest_type(prog, out[-1]["samples"])
    return sorted(out, key=lambda r: -r["count"])


@router.get("/unparsed")
def unparsed(request: Request, hours: int = Query(24, ge=1, le=720),
             ctx: Ctx = Depends(require("logs:read"))) -> dict:
    try:
        resp = client_for(request).search("siem-unparsed-*", unparsed_query(hours))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    hidden = ignored(state(request).settings.secrets_dir)
    return {"hours": hours, "sources": [s for s in parse_unparsed(resp) if s["ip"] not in hidden]}


class IgnoreIn(BaseModel):
    ip: str = Field(max_length=45)


@router.post("/unparsed/ignore")
def ignore_source(body: IgnoreIn, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("sources:write"))) -> dict:
    """Quelle ausblenden („ablehnen“): erscheint nicht mehr in der Liste (Daten bleiben bis zur Retention erhalten)."""
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))
    except ValueError as exc:
        raise error(400, "invalid_request") from exc
    secrets = state(request).settings.secrets_dir
    items = sorted(ignored(secrets) | {ip})[:1000]
    (secrets / "unparsed-ignore.json").write_text(json.dumps(items), "utf-8")
    state(request).audit.append(db, actor=ctx.user.username, action="source.ignore", target=ip, ip=ctx.ip, details={})
    return {"ignored": items}


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


SAMPLE_MAX = 50


@router.get("/unparsed/sample")
def unparsed_sample(request: Request, ip: str = Query(max_length=45), program: str = Query("", max_length=64),
                    limit: int = Query(20, ge=1, le=SAMPLE_MAX), db: DbSession = Depends(get_db),
                    ctx: Ctx = Depends(require("logs:read"))) -> dict:
    """Pseudonymisierte Rohzeilen einer nicht erkannten Quelle (Probenexport für neue Parser, Issue #26)."""
    must: list[dict[str, Any]] = [{"term": {"observer.ip": ip}}]
    if program:
        must.append({"term": {"process.name": program}})
    body = {"size": limit, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": must}},
            "_source": ["event.original", "host.hostname", "user.name"]}
    try:
        resp = client_for(request).search("siem-unparsed-*", body)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    hits = [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]
    raw = [str(h.get("event", {}).get("original", "")) for h in hits]
    hosts = sorted({str(h["host"]["hostname"]) for h in hits if h.get("host", {}).get("hostname")})
    users = sorted({str(h["user"]["name"]) for h in hits if h.get("user", {}).get("name")})
    pseudo = Pseudonymizer(state(request).settings.secrets_dir / "pseudonyms.json", hosts, users)
    lines = pseudo.lines([r[:4000] for r in raw if r])
    state(request).audit.append(db, actor=ctx.user.username, action="logs.sample_export", target=f"{program}",
                                ip=ctx.ip, details={"lines": len(lines)})
    return {"lines": lines}
