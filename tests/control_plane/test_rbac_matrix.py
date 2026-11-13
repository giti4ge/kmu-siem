"""Rollen-Matrix (Abnahmekriterium Phase 2): jede geschützte Route × jede vordefinierte Rolle.

Die Tests leiten die nötige Berechtigung aus der Route selbst ab (deps.require) – kommt eine
neue Route ohne Berechtigungsprüfung hinzu, schlägt test_every_api_route_is_protected fehl.
"""

from __future__ import annotations

import re

import pytest
from fastapi.routing import APIRoute

from siem_api.security import rbac

# Ohne Berechtigung (nur Anmeldung bzw. öffentlich) – bewusst und abschließend
UNPROTECTED = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/totp/verify"),
    ("POST", "/api/auth/totp/setup"),
    ("POST", "/api/auth/totp/enable"),
    ("POST", "/api/auth/password"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/auth/me"),
}

# Erwartete Rechte der vordefinierten Rollen (fachliche Soll-Matrix, unabhängig vom Code)
EXPECTED = {
    "system-admin": {"users:read", "users:write", "audit:read", "system:read", "system:write"},
    "security-analyst": {"alerts:read", "alerts:write", "rules:write", "logs:read"},
    "auditor": {"users:read", "audit:read", "system:read", "logs:read"},
    "privacy-officer": {"privacy:approve", "audit:read", "reports:read"},
    "report-recipient": {"reports:read"},
}
FORBIDDEN = {
    "system-admin": {"privacy:approve", "logs:approve"},
    "security-analyst": {"users:read", "users:write", "audit:read", "system:write", "privacy:read"},
    "auditor": {"users:write", "system:write", "alerts:write"},
    "privacy-officer": {"users:read", "logs:read", "system:read"},
    "report-recipient": {"users:read", "audit:read", "alerts:read", "logs:read"},
}


def route_permission(route: APIRoute) -> str | None:
    def walk(dep):
        perm = getattr(dep.call, "permission", None)
        if perm:
            return perm
        for sub in dep.dependencies:
            found = walk(sub)
            if found:
                return found
        return None
    return walk(route.dependant)


def _walk(routes):
    for r in routes:
        if isinstance(r, APIRoute):
            yield r
        elif hasattr(r, "original_router"):  # FastAPI ≥ 0.16x: eingebundene Router
            yield from _walk(r.original_router.routes)


def api_routes(app):
    found = [(m, r) for r in _walk(app.routes) if r.path.startswith("/api/") for m in r.methods]
    # Schutz gegen leere Ergebnisse (sonst bestünden alle Prüfungen ohne Wirkung)
    assert len(found) >= 20, f"nur {len(found)} API-Routen gefunden"
    return found


def test_builtin_roles_match_expected_matrix():
    for role, must in EXPECTED.items():
        perms = set(rbac.BUILTIN_ROLES[role]["permissions"])
        assert must <= perms, (role, must - perms)
        assert not (FORBIDDEN[role] & perms), (role, FORBIDDEN[role] & perms)
    assert rbac.BUILTIN_ROLES["system-admin"]["mfa_required"] is True


def test_every_api_route_is_protected(app):
    for method, route in api_routes(app):
        if (method, route.path) in UNPROTECTED:
            continue
        assert route_permission(route), f"{method} {route.path} ohne Berechtigungsprüfung"


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "999999", path)


@pytest.mark.parametrize("role", list(rbac.BUILTIN_ROLES))
def test_matrix_enforced_per_route(h, role):
    h.create_user("u", [role])
    c = h.login("u")
    assert c.stage == "ok"
    perms = set(rbac.BUILTIN_ROLES[role]["permissions"])
    checked = 0
    for method, route in api_routes(h.app):
        perm = route_permission(route)
        if not perm:
            continue
        r = c.request(method, _concrete(route.path), json={} if method in ("POST", "PATCH", "PUT") else None)
        if perm in perms:
            # Berechtigt: nie 401/403 (404/409/422 wegen Testdaten sind in Ordnung)
            assert r.status_code not in (401, 403), (role, method, route.path, r.status_code, r.text)
        else:
            assert r.status_code == 403, (role, method, route.path, r.status_code)
            assert r.json()["detail"]["error"] == "forbidden"
        checked += 1
    assert checked >= 12


def test_unauthenticated_gets_401_everywhere(client, app):
    for method, route in api_routes(app):
        if (method, route.path) in UNPROTECTED:
            continue
        r = client.request(method, _concrete(route.path), json={} if method in ("POST", "PATCH") else None)
        assert r.status_code == 401, (method, route.path, r.status_code)


def test_custom_role_grants_exactly_its_permissions(h):
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    r = adm.post("/api/roles", json={"name": "nur-audit", "permissions": ["audit:read"],
                                      "data_scope": {"categories": ["firewall"]}})
    assert r.status_code == 201, r.text
    assert adm.post("/api/roles", json={"name": "kaputt", "permissions": ["gibt:esnicht"]}).status_code == 400
    h.create_user("eva", ["nur-audit"])
    eva = h.login("eva")
    assert eva.get("/api/audit").status_code == 200
    assert eva.get("/api/users").status_code == 403
    # Rechte entziehen wirkt sofort (auch in bestehender Sitzung)
    role_id = r.json()["id"]
    assert adm.patch(f"/api/roles/{role_id}", json={"permissions": []}).status_code == 200
    assert eva.get("/api/audit").status_code == 403


def test_builtin_roles_immutable(h):
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    roles = {r["name"]: r["id"] for r in adm.get("/api/roles").json()}
    assert adm.patch(f"/api/roles/{roles['auditor']}", json={"permissions": []}).status_code == 409
    assert adm.delete(f"/api/roles/{roles['auditor']}").status_code == 409


def test_last_admin_protected(h):
    h.create_user("adm", ["system-admin"])
    adm = h.login("adm")
    me = adm.get("/api/auth/me").json()["user"]["id"]
    assert adm.patch(f"/api/users/{me}", json={"roles": ["auditor"]}).json()["detail"]["error"] == "cannot_demote_self"
    assert adm.patch(f"/api/users/{me}", json={"enabled": False}).status_code == 409
    assert adm.delete(f"/api/users/{me}").json()["detail"]["error"] == "cannot_delete_self"
    # Zweiter Admin kann den ersten entfernen; den letzten verbleibenden aber nicht
    h.create_user("adm2", ["system-admin"])
    adm2 = h.login("adm2")
    assert adm2.delete(f"/api/users/{me}").status_code == 204
    me2 = adm2.get("/api/auth/me").json()["user"]["id"]
    assert adm2.delete(f"/api/users/{me2}").status_code == 409
