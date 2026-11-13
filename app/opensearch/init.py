#!/usr/bin/env python3
"""OpenSearch-Initialisierung der KMU-SIEM Appliance (nur Python-Standardbibliothek).

Befehle:
  init.py wait   [--timeout S]        auf Erreichbarkeit/Cluster-Status warten
  init.py apply                       Index-Templates und ISM-Richtlinien je Kategorie (idempotent)
  init.py find   --index P --text T   Ereignis mit Text T suchen (Selbsttest); Exit 0 = gefunden
  init.py count  --index P [--text T] Anzahl Ereignisse ausgeben
  init.py show                        installierte Templates/Richtlinien ausgeben

Verbindung: --url (https://127.0.0.1:9200), --ca, --user (admin), --password-file.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

# Kategorien und Standard-Aufbewahrung in Tagen (SPEC 4.5); "ot" ist reserviert.
CATEGORIES: dict[str, int] = {
    "firewall": 180,
    "windows": 180,
    "linux": 180,
    "network": 180,
    "edr": 180,
    "av": 180,
    "asset": 180,
    "alerts": 365,
    "audit": 365,
    "infra": 180,
    "system": 90,
    "unparsed": 14,
}
HOT_DAYS = 7
PREFERRED_CODEC = "zstd_no_dict"
FALLBACK_CODEC = "best_compression"

IP = {"type": "ip"}
KW = {"type": "keyword", "ignore_above": 1024}
LONG = {"type": "long"}
DATE = {"type": "date"}

# Gemeinsame ECS-Grundzuordnung (wird je Kategorie in späteren Phasen erweitert)
MAPPINGS: dict[str, Any] = {
    "dynamic_templates": [
        {"strings_as_keyword": {"match_mapping_type": "string", "mapping": KW}},
    ],
    "properties": {
        "@timestamp": DATE,
        "message": {"type": "text"},
        "event": {"properties": {
            "original": {"type": "keyword", "index": False, "doc_values": False},
            "kind": KW, "category": KW, "type": KW, "action": KW, "outcome": KW,
            "dataset": KW, "module": KW, "severity": LONG, "ingested": DATE, "created": DATE,
        }},
        "observer": {"properties": {"ip": IP, "hostname": KW, "name": KW, "vendor": KW, "product": KW, "type": KW}},
        "host": {"properties": {"ip": IP, "hostname": KW, "name": KW}},
        "source": {"properties": {"ip": IP, "port": LONG, "mac": KW, "domain": KW}},
        "destination": {"properties": {"ip": IP, "port": LONG, "mac": KW, "domain": KW}},
        "client": {"properties": {"ip": IP, "port": LONG}},
        "server": {"properties": {"ip": IP, "port": LONG}},
        "user": {"properties": {"name": KW, "domain": KW, "id": KW}},
        "process": {"properties": {"name": KW, "pid": LONG}},
        "log": {"properties": {"level": KW}},
        "siem": {"properties": {"category": KW, "collector": KW, "pipeline": KW, "peer": KW}},
    },
}


class OS:
    """Minimaler OpenSearch-Client."""

    def __init__(self, url: str, ca: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca)
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def request(self, method: str, path: str, body: Any = None, ok404: bool = False) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)  # noqa: S310 – feste https-URL
        req.add_header("Authorization", self.auth)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:  # noqa: S310
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = raw.decode(errors="replace")
            if exc.code == 404 and ok404:
                return 404, payload
            raise RuntimeError(f"{method} {path} → HTTP {exc.code}: {str(payload)[:600]}") from exc


def template_body(category: str, codec: str) -> dict[str, Any]:
    return {
        "index_patterns": [f"siem-{category}-*"],
        "priority": 100,
        "template": {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s",
                    "codec": codec,
                    "mapping": {"total_fields": {"limit": 3000}},
                }
            },
            "mappings": MAPPINGS,
        },
        "_meta": {"managed_by": "kmu-siem", "schema_version": SCHEMA_VERSION},
    }


def policy_body(category: str, retention_days: int) -> dict[str, Any]:
    warm_after = min(HOT_DAYS, max(retention_days - 1, 1))
    return {
        "policy": {
            "description": (
                f"KMU-SIEM {category}: hot {warm_after} d, danach read_only + force_merge, "
                f"löschen nach {retention_days} d"
            ),
            "default_state": "hot",
            "states": [
                {"name": "hot", "actions": [],
                 "transitions": [{"state_name": "warm", "conditions": {"min_index_age": f"{warm_after}d"}}]},
                {"name": "warm", "actions": [{"read_only": {}}, {"force_merge": {"max_num_segments": 1}}],
                 "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{retention_days}d"}}]},
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": [f"siem-{category}-*"], "priority": 100}],
        }
    }


def _policy_core(policy: dict[str, Any]) -> Any:
    """Vergleichbarer Kern einer Richtlinie (ohne Server-Metadaten)."""
    p = policy.get("policy", policy)
    return {
        "description": p.get("description"),
        "default_state": p.get("default_state"),
        "states": [{"name": s["name"], "actions": [{k: v for k, v in a.items() if k != "retry"} for a in s["actions"]],
                    "transitions": s["transitions"]} for s in p.get("states", [])],
        "ism_template": [{"index_patterns": t["index_patterns"], "priority": t["priority"]}
                         for t in (p.get("ism_template") or [])],
    }


def apply(client: OS, retention: dict[str, int]) -> dict[str, Any]:
    report: dict[str, Any] = {"templates": {}, "policies": {}, "codec": PREFERRED_CODEC}
    codec = PREFERRED_CODEC
    for cat in CATEGORIES:
        name = f"siem-{cat}"
        body = template_body(cat, codec)
        status, current = client.request("GET", f"/_index_template/{name}", ok404=True)
        existing = None
        if status == 200:
            existing = current["index_templates"][0]["index_template"]
            codec_in_use = existing.get("template", {}).get("settings", {}).get("index", {}).get("codec", codec)
            body = template_body(cat, codec_in_use)
        unchanged = (
            existing is not None
            and existing.get("_meta") == body["_meta"]
            and existing.get("index_patterns") == body["index_patterns"]
        )
        if unchanged:
            report["templates"][name] = "unverändert"
        else:
            try:
                client.request("PUT", f"/_index_template/{name}", body)
            except RuntimeError as exc:
                if codec != FALLBACK_CODEC and "codec" in str(exc).lower():
                    codec = FALLBACK_CODEC
                    report["codec"] = codec
                    client.request("PUT", f"/_index_template/{name}", template_body(cat, codec))
                else:
                    raise
            report["templates"][name] = "angelegt" if not existing else "aktualisiert"

        desired = policy_body(cat, retention.get(cat, CATEGORIES[cat]))
        status, current = client.request("GET", f"/_plugins/_ism/policies/{name}", ok404=True)
        if status == 404:
            client.request("PUT", f"/_plugins/_ism/policies/{name}", desired)
            report["policies"][name] = "angelegt"
        elif _policy_core(current["policy"]) == _policy_core(desired):
            report["policies"][name] = "unverändert"
        else:
            client.request(
                "PUT",
                f"/_plugins/_ism/policies/{name}?if_seq_no={current['_seq_no']}&if_primary_term={current['_primary_term']}",
                desired,
            )
            report["policies"][name] = "aktualisiert"
    return report


def wait(client: OS, timeout: int) -> dict[str, Any]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            _, health = client.request("GET", "/_cluster/health")
            if health["status"] in ("green", "yellow"):
                return health
            last = health["status"]
        except (RuntimeError, OSError) as exc:
            last = str(exc)[:200]
        time.sleep(3)
    raise RuntimeError(f"OpenSearch nicht bereit nach {timeout} s: {last}")


def count(client: OS, index: str, text: str | None) -> int:
    client.request("POST", f"/{index}/_refresh", ok404=True)
    query: dict[str, Any] = {"match_all": {}} if not text else {"match_phrase": {"message": text}}
    # Frisch angelegte Indizes: Shards sind kurz nicht bereit (503 "all shards failed") → wiederholen
    for attempt in range(6):
        try:
            status, res = client.request("POST", f"/{index}/_count", {"query": query}, ok404=True)
            return 0 if status == 404 else int(res["count"])
        except RuntimeError as exc:
            if "HTTP 503" not in str(exc) or attempt == 5:
                raise
            time.sleep(2)
    return 0


JWT_DOMAIN = "siem_jwt"


def security(client: OS, jwt_key_b64: str, kibanaserver_password: str,
             api_password: str | None = None) -> dict[str, Any]:
    """SSO für Dashboards (idempotent über die REST-API, auch für bestehende Installationen).

    - JWT-Authentifizierung (HS256, Schlüssel je Installation): Die Control-Plane stellt nach
      vollständiger Anmeldung ein kurzlebiges Token aus, nginx reicht es an Dashboards weiter.
      Kein Vertrauen in Proxy-Header – andere Prozesse auf 127.0.0.1 können nichts fälschen.
    - Rolle siem_reader (nur Lesen auf siem-*) und Zuordnungen, Dienstkonto kibanaserver.
    """
    _, cfg = client.request("GET", "/_plugins/_security/api/securityconfig")
    dynamic = cfg["config"]["dynamic"]
    domain = {
        "description": "SSO aus der KMU-SIEM Control-Plane (JWT)",
        "http_enabled": True,
        "transport_enabled": False,
        "order": 0,
        "http_authenticator": {
            "type": "jwt",
            "challenge": False,
            "config": {"signing_key": jwt_key_b64, "jwt_header": "Authorization",
                       "subject_key": "sub", "roles_key": "roles", "jwt_clock_skew_tolerance_seconds": 30},
        },
        "authentication_backend": {"type": "noop"},
    }
    # JWT zuerst; Basic danach und ohne Challenge – eine Basic-Domain mit Challenge an erster
    # Stelle beantwortet jede Anfrage ohne Basic-Zugangsdaten sofort mit 401 (auch Bearer-JWTs).
    # Interne Clients (Vector, kibanaserver, init.py) senden Basic-Zugangsdaten ohnehin direkt.
    basic = dynamic["authc"]["basic_internal_auth_domain"]
    wanted_basic = {**basic, "order": 1,
                    "http_authenticator": {**basic["http_authenticator"], "challenge": False}}
    changed = dynamic["authc"].get(JWT_DOMAIN) != domain or basic != wanted_basic
    if changed:
        dynamic["authc"][JWT_DOMAIN] = domain
        dynamic["authc"]["basic_internal_auth_domain"] = wanted_basic
        client.request("PUT", "/_plugins/_security/api/securityconfig/config", {"dynamic": dynamic})
    client.request("PUT", "/_plugins/_security/api/roles/siem_reader", {
        "description": "KMU-SIEM: Ereignisse lesen (Dashboards)",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [{
            "index_patterns": ["siem-*"],
            "allowed_actions": ["read", "indices:admin/mappings/get", "indices:admin/resolve/index"],
        }],
    })
    client.request("PUT", "/_plugins/_security/api/rolesmapping/siem_reader", {"backend_roles": ["siem_reader"]})
    client.request("PUT", "/_plugins/_security/api/rolesmapping/kibana_user", {"backend_roles": ["siem_reader"]})
    client.request("PUT", "/_plugins/_security/api/internalusers/kibanaserver", {
        "password": kibanaserver_password, "description": "Dienstkonto OpenSearch Dashboards"})
    client.request("PUT", "/_plugins/_security/api/rolesmapping/kibana_server", {"users": ["kibanaserver"]})
    if api_password:
        # Control-Plane: Ereignisse lesen, Alarme/Audit schreiben, Aufbewahrung (ISM) verwalten
        client.request("PUT", "/_plugins/_security/api/roles/siem_api", {
            "description": "KMU-SIEM Control-Plane",
            "cluster_permissions": [
                "cluster_monitor", "cluster_composite_ops_ro",
                "cluster:admin/opendistro/ism/policy/*", "cluster:admin/opendistro/ism/managedindex/*",
            ],
            "index_permissions": [
                {"index_patterns": ["siem-*"],
                 "allowed_actions": ["read", "indices_monitor", "indices:admin/mappings/get",
                                     "indices:admin/resolve/index"]},
                {"index_patterns": ["siem-alerts-*", "siem-audit-*"],
                 "allowed_actions": ["crud", "create_index", "indices:admin/mapping/put"]},
            ],
        })
        client.request("PUT", "/_plugins/_security/api/rolesmapping/siem_api", {"users": ["siem_api"]})
        client.request("PUT", "/_plugins/_security/api/internalusers/siem_api", {
            "password": api_password, "description": "Control-Plane (API)"})
    return {"jwt_domain_changed": changed}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="https://127.0.0.1:9200")
    p.add_argument("--ca", default="/opt/siem/data/secrets/pki/ca.crt")
    p.add_argument("--user", default="admin")
    p.add_argument("--password-file", default="/opt/siem/data/secrets/opensearch-admin.pw")
    p.add_argument("--retention-file", default="/opt/siem/data/app/retention.json")
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("wait")
    w.add_argument("--timeout", type=int, default=300)
    sub.add_parser("apply")
    sub.add_parser("show")
    sec = sub.add_parser("security")
    sec.add_argument("--jwt-key-file", required=True)
    sec.add_argument("--kibanaserver-password-file", required=True)
    sec.add_argument("--api-password-file")
    f = sub.add_parser("find")
    f.add_argument("--index", required=True)
    f.add_argument("--text", required=True)
    f.add_argument("--timeout", type=float, default=10.0)
    c = sub.add_parser("count")
    c.add_argument("--index", required=True)
    c.add_argument("--text")
    args = p.parse_args(argv)

    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    client = OS(args.url, args.ca, args.user, password)
    try:
        if args.cmd == "wait":
            print(json.dumps(wait(client, args.timeout)))
        elif args.cmd == "apply":
            retention: dict[str, int] = {}
            rf = Path(args.retention_file)
            if rf.exists():
                stored = json.loads(rf.read_text(encoding="utf-8"))
                retention = {k: int(v) for k, v in stored.items() if k in CATEGORIES}
            print(json.dumps(apply(client, retention), ensure_ascii=False, indent=2))
        elif args.cmd == "security":
            key = Path(args.jwt_key_file).read_text(encoding="utf-8").strip()
            kpw = Path(args.kibanaserver_password_file).read_text(encoding="utf-8").strip()
            apw = (Path(args.api_password_file).read_text(encoding="utf-8").strip()
                   if args.api_password_file else None)
            print(json.dumps(security(client, key, kpw, apw)))
        elif args.cmd == "show":
            _, t = client.request("GET", "/_index_template/siem-*", ok404=True)
            _, pol = client.request("GET", "/_plugins/_ism/policies", ok404=True)
            print(json.dumps({"templates": [x["name"] for x in (t or {}).get("index_templates", [])],
                              "policies": [x["_id"] for x in (pol or {}).get("policies", [])]}, indent=2))
        elif args.cmd == "find":
            start = time.time()
            while time.time() - start < args.timeout:
                if count(client, args.index, args.text) > 0:
                    print(json.dumps({"found": True, "seconds": round(time.time() - start, 2)}))
                    return 0
                time.sleep(0.5)
            print(json.dumps({"found": False, "seconds": args.timeout}))
            return 1
        elif args.cmd == "count":
            print(count(client, args.index, args.text))
    except RuntimeError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
