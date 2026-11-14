"""Parser-Editor (Spec 4.16): eigene Regeln für nicht erkannte Quellen, ohne VRL-Kenntnisse.

Eine Regel besteht aus Name, optionalem Programmnamen (``process.name``), einem regulären Ausdruck mit benannten Gruppen
und einer Zuordnung Gruppe → ECS-Feld (nur Felder aus einer festen Liste). Aus den Regeln erzeugt die Control-Plane
``custom.vrl`` (nur aus geprüften Bausteinen, nie aus freiem Code); Vector wendet sie auf Ereignisse an, die sonst als
``unparsed`` enden. Regex-Funktionen sind auf den gemeinsamen Teil von Python und Rust beschränkt (keine Lookarounds
und Rückverweise), damit der Test im Web-UI das Verhalten in Vector widerspiegelt.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

CATEGORIES = ("firewall", "network", "windows", "linux", "av", "edr", "asset", "infra")
FIELDS = {
    "user.name": "str", "host.name": "str", "source.ip": "ip", "destination.ip": "ip", "source.port": "int",
    "destination.port": "int", "event.action": "str", "event.outcome": "str", "process.name": "str",
    "url.original": "str", "file.path": "str", "network.protocol": "str", "message": "str",
}
OUTCOMES = {"success", "failure", "unknown"}
MAX_RULES = 50
MAX_REGEX = 500
_ID = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_PROGRAM = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
_GROUP = re.compile(r"\(\?P<([A-Za-z][A-Za-z0-9_]*)>")
_FORBIDDEN = re.compile(r"\(\?(?:=|!|<=|<!|>|#|\()|\\[1-9]|\(\?P=|'|\\Z|\\A")


class ParserError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_rule(r: dict[str, Any]) -> dict[str, Any]:
    rid, regex = str(r.get("id", "")), str(r.get("regex", ""))
    program = str(r.get("program") or "")
    if not _ID.match(rid) or not regex or len(regex) > MAX_REGEX or _FORBIDDEN.search(regex):
        raise ParserError("parser_invalid_rule")
    if program and not _PROGRAM.match(program):
        raise ParserError("parser_invalid_rule")
    if r.get("category") not in CATEGORIES:
        raise ParserError("parser_invalid_category")
    try:
        compiled = re.compile(regex)
    except re.error:
        raise ParserError("parser_invalid_regex") from None
    groups = set(_GROUP.findall(regex))
    mapping = r.get("fields") or {}
    if not isinstance(mapping, dict) or not mapping or len(mapping) > 12:
        raise ParserError("parser_invalid_fields")
    for grp, fld in mapping.items():
        if grp not in groups or grp not in compiled.groupindex or fld not in FIELDS:
            raise ParserError("parser_invalid_fields")
    if len(set(mapping.values())) != len(mapping):
        raise ParserError("parser_invalid_fields")
    return {"id": rid, "name": str(r.get("name") or rid)[:64], "program": program, "regex": regex,
            "category": r["category"], "fields": dict(mapping), "enabled": bool(r.get("enabled", True)),
            "action": str(r.get("action") or "")[:48]}


def render_vrl(rules: list[dict[str, Any]]) -> str:
    out = ["# Automatisch erzeugt (Parser-Editor) – nicht von Hand ändern"]
    rules = [r for r in rules if r["enabled"]]
    if not rules:
        return out[0] + "\n. = .\n"
    out += ["if .siem.category == \"unparsed\" {", "  done = false"]
    for r in rules:
        cond = f' && .process.name == "{r["program"]}"' if r["program"] else ""
        out.append(f"  if !done{cond} {{")
        out.append("    m, err = parse_regex(string(.event.original) ?? \"\", r'" + r["regex"] + "')")
        out.append("    if err == null {")
        out.append("      done = true")
        out.append(f'      .siem.category = "{r["category"]}"')
        out.append(f'      .siem.pipeline = "custom.{r["id"]}"')
        out.append(f'      .event.dataset = "custom.{r["id"]}"')
        if r["action"]:
            out.append(f'      .event.action = "{r["action"]}"')
        for grp, fld in sorted(r["fields"].items()):
            kind = FIELDS[fld]
            path = "." + fld
            if kind == "int":
                out.append(f"      v_{grp}, e_{grp} = to_int(m.{grp})")
                out.append(f"      if e_{grp} == null {{ {path} = v_{grp} }}")
            elif kind == "ip":
                out.append(f"      _, e_{grp} = ip_pton(string(m.{grp}) ?? \"\")")
                out.append(f"      if e_{grp} == null {{ {path} = m.{grp} }}")
            elif fld == "event.outcome":
                out.append(f"      o_{grp} = downcase(string(m.{grp}) ?? \"\")")
                known = 'includes(["success", "failure"], o_' + grp + ")"
                out.append(f'      {path} = if {known} {{ o_{grp} }} else {{ "unknown" }}')
            else:
                out.append(f"      {path} = m.{grp}")
        out.append("    }")
        out.append("  }")
    out.append("}")
    return "\n".join(out) + "\n"


def test_rule(rule: dict[str, Any], samples: list[str], program: str = "") -> list[dict[str, Any]]:
    """Regel auf Beispielzeilen anwenden (Python-Regex, gleiche Gruppensemantik wie in Vector)."""
    r = validate_rule(rule)
    rx = re.compile(r["regex"])
    out = []
    for s in samples[:50]:
        m = rx.search(s[:4000]) if not r["program"] or r["program"] == program else None
        fields = {fld: m.group(g) for g, fld in r["fields"].items() if m and m.group(g) is not None}
        out.append({"line": s[:200], "match": bool(m), "fields": fields})
    return out


class Store:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.path = directory / "custom_parsers.json"

    def rules(self) -> list[dict[str, Any]]:
        try:
            d = json.loads(self.path.read_text("utf-8"))
            return d if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def save(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(rules) > MAX_RULES:
            raise ParserError("parser_too_many")
        clean = [validate_rule(r) for r in rules]
        if len({r["id"] for r in clean}) != len(clean):
            raise ParserError("parser_invalid_rule")
        self.dir.mkdir(parents=True, exist_ok=True)
        self._write("custom_parsers.json", json.dumps(clean))
        self._write("custom.vrl", render_vrl(clean))
        return clean

    def ensure_default(self) -> None:
        if not (self.dir / "custom.vrl").exists():
            self.dir.mkdir(parents=True, exist_ok=True)
            self._write("custom.vrl", render_vrl([]))

    def _write(self, name: str, text: str) -> None:
        tmp = self.dir / (name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, self.dir / name)
