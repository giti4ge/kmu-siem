"""Retention je Log-Kategorie (ISM-Richtlinien), mit Speicher-Plausibilisierung (Spec 4.5)."""

from __future__ import annotations

import copy
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ..deps import Ctx, error, get_db, require, state
from ..opensearch import OpenSearchClient, OpenSearchUnavailable
from .logs import CATEGORIES

router = APIRouter(tags=["retention"], prefix="/api/retention")

MIN_DAYS, MAX_DAYS = 7, 730
HOT_DAYS = 7
# Anteil des Datenträgers, den die Aufbewahrung höchstens belegen darf (Watermark low = 85 %)
MAX_FILL = 0.80


class RetentionIn(BaseModel):
    days: dict[str, int] = Field(max_length=32)


def client_for(request: Request) -> OpenSearchClient:
    st = state(request)
    return OpenSearchClient(st.settings.opensearch_url, st.settings.secrets_dir)


def delete_days(policy: dict[str, Any]) -> int | None:
    """Aufbewahrung in Tagen aus dem Übergang warm → delete."""
    for s in policy.get("policy", {}).get("states", []):
        for t in s.get("transitions", []):
            if t.get("state_name") == "delete":
                age = str(t.get("conditions", {}).get("min_index_age", ""))
                if age.endswith("d") and age[:-1].isdigit():
                    return int(age[:-1])
    return None


def with_days(policy: dict[str, Any], category: str, days: int) -> dict[str, Any]:
    """Richtlinie mit neuer Aufbewahrung (gleiche Struktur wie init.py/policy_body)."""
    body = copy.deepcopy({"policy": {k: v for k, v in policy["policy"].items()
                                     if k in ("description", "default_state", "states", "ism_template")}})
    warm_after = min(HOT_DAYS, max(days - 1, 1))
    body["policy"]["description"] = (f"KMU-SIEM {category}: hot {warm_after} d, danach read_only + force_merge, "
                                     f"löschen nach {days} d")
    for s in body["policy"]["states"]:
        for t in s.get("transitions", []):
            if t["state_name"] == "warm":
                t["conditions"]["min_index_age"] = f"{warm_after}d"
            elif t["state_name"] == "delete":
                t["conditions"]["min_index_age"] = f"{days}d"
    return body


def daily_bytes(indices: list[dict[str, Any]]) -> dict[str, float]:
    """Mittleres Tagesvolumen je Kategorie aus _cat/indices (Größe ÷ Anzahl Tagesindizes)."""
    sizes: dict[str, list[int]] = {}
    for ix in indices:
        parts = str(ix.get("index", "")).split("-")
        if len(parts) >= 3 and parts[0] == "siem" and parts[1] in CATEGORIES:
            sizes.setdefault(parts[1], []).append(int(ix.get("store.size") or 0))
    return {c: sum(v) / len(v) for c, v in sizes.items() if v}


def storage_check(days: dict[str, int], per_day: dict[str, float], total_bytes: int) -> dict[str, Any]:
    need = sum(per_day.get(c, 0.0) * d for c, d in days.items())
    return {"needed_bytes": int(need), "total_bytes": total_bytes,
            "ok": total_bytes <= 0 or need <= total_bytes * MAX_FILL}


def _load(request: Request) -> tuple[dict[str, dict], dict[str, float], int]:
    c = client_for(request)
    policies: dict[str, dict] = {}
    for cat in CATEGORIES:
        p = c.request("GET", f"/_plugins/_ism/policies/siem-{cat}")
        if p:
            policies[cat] = p
    indices = c.request("GET", "/_cat/indices/siem-*?format=json&bytes=b&h=index,store.size") or []
    fs = (c.request("GET", "/_nodes/stats/fs") or {}).get("nodes", {})
    total = sum(int(n.get("fs", {}).get("total", {}).get("total_in_bytes", 0)) for n in fs.values())
    return policies, daily_bytes(indices), total


def _view(policies: dict[str, dict], per_day: dict[str, float], total: int) -> dict[str, Any]:
    days = {c: delete_days(policies[c]) if c in policies else None for c in CATEGORIES}
    eff = {c: d for c, d in days.items() if d}
    return {
        "min_days": MIN_DAYS, "max_days": MAX_DAYS,
        "categories": [{"category": c, "days": days[c], "daily_bytes": int(per_day.get(c, 0))} for c in CATEGORIES],
        "storage": storage_check(eff, per_day, total),
    }


@router.get("")
def get_retention(request: Request, ctx: Ctx = Depends(require("privacy:read"))) -> dict:
    try:
        return _view(*_load(request))
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc


@router.put("")
def put_retention(body: RetentionIn, request: Request, db: DbSession = Depends(get_db),
                  ctx: Ctx = Depends(require("privacy:write"))) -> dict:
    for cat, d in body.days.items():
        if cat not in CATEGORIES:
            raise error(400, "retention_unknown_category")
        if not MIN_DAYS <= d <= MAX_DAYS:
            raise error(400, "retention_out_of_range")
    c = client_for(request)
    try:
        policies, per_day, total = _load(request)
        current = {k: delete_days(v) for k, v in policies.items()}
        merged = {k: v for k, v in current.items() if v}
        merged.update(body.days)
        if not storage_check(merged, per_day, total)["ok"]:
            raise error(409, "retention_exceeds_storage")
        changed = {k: d for k, d in body.days.items() if k in policies and current.get(k) != d}
        for cat, d in changed.items():
            p = policies[cat]
            c.request("PUT", f"/_plugins/_ism/policies/siem-{cat}?if_seq_no={p['_seq_no']}"
                             f"&if_primary_term={p['_primary_term']}", with_days(p, cat, d))
            # bestehende Indizes auf die neue Richtlinienversion umstellen (Zustand bleibt erhalten)
            try:
                c.request("POST", f"/_plugins/_ism/change_policy/siem-{cat}-*", {"policy_id": f"siem-{cat}"})
            except OpenSearchUnavailable:
                pass
        policies, per_day, total = _load(request)
    except OpenSearchUnavailable as exc:
        raise error(status.HTTP_503_SERVICE_UNAVAILABLE, "opensearch_unavailable") from exc
    if changed:
        state(request).audit.append(db, actor=ctx.user.username, action="retention.set", target="ism", ip=ctx.ip,
                                    details={"changed": {k: {"from": current.get(k), "to": v} for k, v in changed.items()}})
    return _view(policies, per_day, total)
