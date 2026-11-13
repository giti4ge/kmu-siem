#!/usr/bin/env python3
"""i18n-Prüfung des Frontends (Spec 5.2: keine hartcodierten Texte, DE/EN vollständig).

1. de.json und en.json enthalten dieselben Schlüssel.
2. Jeder statische Schlüssel t("…") im Code existiert in den Katalogen.
3. Kein sichtbarer Text direkt im JSX (>Text<) und keine Texte in placeholder/title/aria-label.
4. Jeder Fehlerschlüssel der API (error(…, "…") im Backend) hat eine Übersetzung.
Exit 1 bei Verstößen.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FE = ROOT / "app" / "control-plane" / "frontend" / "src"
BE = ROOT / "app" / "control-plane" / "backend" / "siem_api"

JSX_TEXT = re.compile(r">\s*([^<>{}\n]*[A-Za-zÄÖÜäöüß]{2,}[^<>{}\n]*)\s*<")
ATTR_TEXT = re.compile(r"""\b(placeholder|title|aria-label|alt)="([^"]*[A-Za-zÄÖÜäöü]{2,}[^"]*)\"""")
T_CALL = re.compile(r"""\bt\(\s*["']([a-z0-9_.-]+)["']""")
API_ERR = re.compile(r"""error\(\s*status\.\w+,\s*["']([a-z0-9_]+)["']\)""")
# Code-Bezeichner, die wie Text aussehen, aber keiner sind
ALLOWED_TEXT = {"KMU-SIEM"}


def flatten(d: dict, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    for k, v in d.items():
        full = f"{prefix}{k}"
        keys |= flatten(v, f"{full}.") if isinstance(v, dict) else {full}
    return keys


def main() -> int:
    problems: list[str] = []
    de = flatten(json.loads((FE / "i18n" / "de.json").read_text(encoding="utf-8")))
    en = flatten(json.loads((FE / "i18n" / "en.json").read_text(encoding="utf-8")))
    problems += [f"nur in de.json: {k}" for k in sorted(de - en)]
    problems += [f"nur in en.json: {k}" for k in sorted(en - de)]

    for f in sorted(FE.rglob("*.tsx")):
        text = f.read_text(encoding="utf-8")
        rel = f.relative_to(ROOT)
        for key in T_CALL.findall(text):
            if key not in de:
                problems.append(f"{rel}: Schlüssel fehlt im Katalog: {key}")
        for m in JSX_TEXT.finditer(text):
            if m.start() > 0 and text[m.start() - 1] in "=-":  # "=>"/"->" ist kein Tag-Ende
                continue
            s = m.group(1).strip()
            # Typ-Parameter und Vergleiche (z. B. <string[]>, a < b) sind kein Text
            if s in ALLOWED_TEXT or "=>" in s or s.startswith(("&&", "||", "?")) or "(" in s or ")" in s:
                continue
            line = text.count("\n", 0, m.start()) + 1
            problems.append(f"{rel}:{line}: hartcodierter Text: {s!r}")
        for m in ATTR_TEXT.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            problems.append(f"{rel}:{line}: hartcodierter Text in {m.group(1)}: {m.group(2)!r}")

    for f in sorted(BE.rglob("*.py")):
        for key in API_ERR.findall(f.read_text(encoding="utf-8")):
            if f"errors.{key}" not in de:
                problems.append(f"{f.relative_to(ROOT)}: API-Fehler ohne Übersetzung: errors.{key}")
    for key in ("stage_mfa_verify", "stage_password_change", "stage_mfa_enroll"):
        if f"errors.{key}" not in de:
            problems.append(f"Fehlende Übersetzung: errors.{key}")

    for p in problems:
        print(p)
    print(f"i18n: {len(de)} Schlüssel, {len(problems)} Probleme")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
