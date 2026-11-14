"""Rückwirkende Verarbeitung (Spec 4.16): gepufferte "unparsed"-Ereignisse einer freigegebenen Quelle erneut einspielen.

Ablauf: Ereignisse der Quell-IP aus ``siem-unparsed-*`` lesen, als Syslog-Felder rekonstruieren und an die Vector-Quelle
``replay_in`` (Loopback 10603) senden; dort laufen sie mit Original-Zeitstempel durch die Geräteerkennung und landen
im passenden Parser/Index. Danach werden die Originale aus ``siem-unparsed-*`` entfernt. Erneut eingespielte Ereignisse
werden nicht noch einmal im Archiv abgelegt (die Originale stehen dort bereits).
"""

from __future__ import annotations

import json
import socket
from typing import Any

from .opensearch import OpenSearchClient

MAX_EVENTS = 5000
REPLAY_ADDR = ("127.0.0.1", 10603)


def to_line(doc: dict[str, Any]) -> dict[str, Any] | None:
    src = doc.get("_source", {})
    msg = src.get("event", {}).get("original") or src.get("message")
    ip = src.get("observer", {}).get("ip")
    if not msg or not ip:
        return None
    sev = src.get("log", {}).get("syslog", {}).get("severity", {}).get("name")
    fac = src.get("log", {}).get("syslog", {}).get("facility", {}).get("name")
    out: dict[str, Any] = {"source_ip": str(ip), "message": str(msg), "@timestamp": src.get("@timestamp")}
    for key, val in (("hostname", src.get("host", {}).get("hostname")), ("appname", src.get("process", {}).get("name")),
                     ("procid", src.get("process", {}).get("pid")), ("severity", sev), ("facility", fac)):
        if val is not None:
            out[key] = val
    return out


def send(lines: list[dict[str, Any]], addr: tuple[str, int] = REPLAY_ADDR) -> None:
    payload = "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in lines).encode()
    with socket.create_connection(addr, timeout=10) as s:
        s.sendall(payload)


def replay_source(client: OpenSearchClient, ip: str, sender=send) -> dict[str, Any]:
    q = {"size": MAX_EVENTS, "sort": [{"@timestamp": "asc"}], "_source": True,
         "query": {"bool": {"filter": [{"term": {"observer.ip": ip}}]}}}
    resp = client.search("siem-unparsed-*", q)
    hits = resp.get("hits", {}).get("hits", [])
    pairs = [(h, to_line(h)) for h in hits]
    lines = [ln for _h, ln in pairs if ln]
    if not lines:
        return {"replayed": 0, "remaining": 0}
    sender(lines)
    ids_by_index: dict[str, list[str]] = {}
    for h, ln in pairs:
        if ln:
            ids_by_index.setdefault(h["_index"], []).append(h["_id"])
    for index, ids in ids_by_index.items():
        for i in range(0, len(ids), 500):
            client.request("POST", f"/{index}/_delete_by_query?refresh=true",
                           {"query": {"ids": {"values": ids[i:i + 500]}}})
    total = resp.get("hits", {}).get("total", {})
    total = total.get("value", len(hits)) if isinstance(total, dict) else len(hits)
    return {"replayed": len(lines), "remaining": max(0, total - len(hits))}
