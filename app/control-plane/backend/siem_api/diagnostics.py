"""Diagnosepaket (Issue #27): Versionen, Status, Fehlerzeilen, Kennzahlen – ohne Geheimnisse und Ereignisinhalte."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from . import __version__, hostd
from .anonymizer import Pseudonymizer
from .config import Settings
from .opensearch import OpenSearchClient, OpenSearchUnavailable

SOURCES = ("install", "siem-hostd", "docker", "opensearch", "vector", "proxy", "api")
_ERROR = re.compile(r"(?i)\b(error|fehler|fail|failed|fehlgeschlagen|critical|fatal|exception|traceback|warn)")
_SECRET = re.compile(
    r"(?i)((?:pass(?:word|wd)?|kennwort|secret|token|api[_-]?key|private[_-]?key|authorization|bearer|cookie|"
    r"totp|master[_-]?key|credential)[\w-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)")
_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_LONG = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b")


def scrub(text: str) -> str:
    """Entfernt Kennwörter, Token und Schlüssel aus einer Zeile."""
    t = _BLOCK.sub("[GEHEIMNIS]", text)
    t = _SECRET.sub(lambda m: m.group(1) + "[GEHEIMNIS]", t)
    return _LONG.sub("[GEHEIMNIS]", t)


def error_lines(lines: list[str], limit: int = 60) -> list[str]:
    return [scrub(ln)[:400] for ln in lines if _ERROR.search(ln)][-limit:]


def build(settings: Settings, actor: str, maintenance: dict[str, Any], pseudonymize: bool = True) -> dict[str, Any]:
    pkg: dict[str, Any] = {
        "created": datetime.now(UTC).isoformat(timespec="seconds"), "version": __version__,
        "hinweis": "Enthält keine Geheimnisse und keine Ereignisinhalte.", "maintenance": maintenance,
        "config": {"opensearch_url": settings.opensearch_url, "session_idle_minutes": settings.session_idle_minutes,
                   "session_max_hours": settings.session_max_hours, "lockout_threshold": settings.lockout_threshold},
    }
    try:
        pkg["host"] = hostd.call(settings.hostd_socket, "system.status", {}, actor=actor)
    except (hostd.HostdUnavailable, hostd.HostdRejected) as exc:
        pkg["host"] = {"error": str(exc)[:200]}
    logs: dict[str, list[str]] = {}
    for src in SOURCES:
        try:
            r = hostd.call(settings.hostd_socket, "system.logs", {"source": src, "lines": 500, "query": ""},
                           actor=actor)
            rows = r.get("lines") if isinstance(r, dict) else r
            logs[src] = error_lines([str(x) for x in rows or []])
        except (hostd.HostdUnavailable, hostd.HostdRejected):
            logs[src] = []
    pkg["errors"] = logs
    try:
        c = OpenSearchClient(settings.opensearch_url, settings.secrets_dir)
        pkg["opensearch"] = {
            "health": c.request("GET", "/_cluster/health"),
            "indices": c.request("GET", "/_cat/indices/siem-*?format=json&bytes=b&h=index,docs.count,store.size")
            or [],
            # Parser-Statistik: Ereignisse je Kategorie und nicht erkannt je Quelle (nur Zahlen)
            "volume_24h": c.search("siem-*", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
                                              "aggs": {"c": {"terms": {"field": "siem.category", "size": 50}}}}
                                   ).get("aggregations", {}).get("c", {}).get("buckets", []),
            "unparsed_by_source": c.search("siem-unparsed-*", {"size": 0, "aggs": {"s": {
                "terms": {"field": "observer.ip", "size": 50}}}}).get("aggregations", {}).get("s", {}).get("buckets", []),  # noqa: E501
        }
    except OpenSearchUnavailable as exc:
        pkg["opensearch"] = {"error": str(exc)[:200]}
    if pseudonymize:
        import json

        host = pkg.get("host") if isinstance(pkg.get("host"), dict) else {}
        known = [str(host[k]) for k in ("hostname", "fqdn") if host.get(k)]
        p = Pseudonymizer(settings.secrets_dir / "pseudonyms.json", known)
        txt = p.line(json.dumps(pkg, ensure_ascii=False))
        p.save()
        pkg = json.loads(txt)
        pkg["pseudonymisiert"] = True
    return pkg
