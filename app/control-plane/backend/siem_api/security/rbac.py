"""Rollen und Berechtigungen (Spec 5.1): Modul × {read, write, approve}.

Die vordefinierten Rollen werden bei jedem Start mit dieser Datei abgeglichen (seed_roles),
damit neue Module nach einem Update automatisch korrekt berechtigt sind. Eigene Rollen
setzen sich aus denselben granularen Berechtigungen zusammen.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Role

# Module gemäß Spec 5.2 (+ users/audit als eigene Bereiche des System-Moduls)
MODULES = (
    "dashboard", "alerts", "logs", "switches", "assets", "sources", "rules",
    "changes", "reports", "archive", "privacy", "system", "users", "audit",
)
ACTIONS = ("read", "write", "approve")
# "approve" (Vier-Augen-Freigaben) gibt es nur, wo Freigaben vorgesehen sind
APPROVABLE = ("logs", "alerts", "archive", "privacy")

PERMISSIONS: tuple[str, ...] = tuple(
    f"{m}:{a}" for m in MODULES for a in ACTIONS if a != "approve" or m in APPROVABLE
)


def _all(action: str, exclude: tuple[str, ...] = ()) -> list[str]:
    return [f"{m}:{action}" for m in MODULES if m not in exclude and f"{m}:{action}" in PERMISSIONS]


SYSTEM_ADMIN = "system-admin"
SECURITY_ANALYST = "security-analyst"
AUDITOR = "auditor"
PRIVACY_OFFICER = "privacy-officer"
REPORT_RECIPIENT = "report-recipient"
MANAGEMENT = "management"

# Vordefinierte Rollen. Der System-Admin hat bewusst KEIN "approve": Freigaben im
# Datenschutzmodus erteilen DSB/Betriebsrat, nicht der Administrator selbst.
BUILTIN_ROLES: dict[str, dict] = {
    SYSTEM_ADMIN: {
        "description": "Vollzugriff auf Konfiguration, Benutzer und Daten (MFA verpflichtend)",
        "mfa_required": True,
        "permissions": _all("read") + _all("write"),
    },
    SECURITY_ANALYST: {
        "description": "Analyse von Alarmen und Ereignissen, Regeln und Assets pflegen",
        "mfa_required": False,
        "permissions": _all("read", exclude=("system", "users", "audit", "privacy"))
        + ["alerts:write", "rules:write", "assets:write", "reports:write", "switches:write"],
    },
    AUDITOR: {
        "description": "Nur lesen, einschließlich Audit-Log",
        "mfa_required": False,
        "permissions": _all("read"),
    },
    PRIVACY_OFFICER: {
        "description": "Datenschutzbeauftragter/Betriebsrat: Freigaben, Zugriffsprotokoll, Reports",
        "mfa_required": False,
        "permissions": ["privacy:read", "privacy:approve", "logs:approve", "alerts:approve",
                        "archive:approve", "audit:read", "reports:read"],
    },
    MANAGEMENT: {
        "description": "Management/Geschäftsführung: Kennzahlen im Dashboard und Reports (reduzierte Sicht)",
        "mfa_required": False,
        "permissions": ["dashboard:read", "reports:read"],
    },
    REPORT_RECIPIENT: {
        "description": "Nur Reports lesen",
        "mfa_required": False,
        "permissions": ["reports:read"],
    },
}


def validate_permissions(perms: list[str]) -> list[str]:
    unknown = sorted(set(perms) - set(PERMISSIONS))
    if unknown:
        raise ValueError(f"Unbekannte Berechtigungen: {', '.join(unknown)}")
    return sorted(set(perms))


def seed_roles(db: Session) -> None:
    """Vordefinierte Rollen anlegen bzw. auf den Stand dieser Version bringen."""
    existing = {r.name: r for r in db.scalars(select(Role)).all()}
    for name, spec in BUILTIN_ROLES.items():
        role = existing.get(name)
        if role is None:
            role = Role(name=name, builtin=True, data_scope={})
            db.add(role)
        role.builtin = True
        role.description = spec["description"]
        role.mfa_required = spec["mfa_required"]
        role.permissions = validate_permissions(spec["permissions"])
    db.commit()


def user_permissions(roles: list[Role]) -> set[str]:
    perms: set[str] = set()
    for role in roles:
        perms.update(role.permissions or [])
    return perms


def mfa_required(roles: list[Role]) -> bool:
    return any(r.mfa_required for r in roles)
