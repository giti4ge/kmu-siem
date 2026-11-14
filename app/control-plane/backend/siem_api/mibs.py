"""MIB-Import (Spec 4.6b, ADR-22): Hersteller-MIBs hochladen und OID-Namen auflösen.

Es werden keine Hersteller-MIBs mitgeliefert. Importierte Dateien (reiner Text, ``.mib``/``.my``/``.txt`` oder ZIP)
werden **nicht ausgeführt und nicht kompiliert**: ein einfacher Textparser liest ``OBJECT IDENTIFIER``- und
``OBJECT-TYPE``-Zuweisungen (``name ... ::= { eltern n }``) und löst sie gegen bekannte Wurzeln und bereits importierte
Module auf. Ergebnis ist eine Namens→OID-Tabelle, aus der im Web-UI eigene OIDs für das Abfrageziel gewählt werden.
Abweichung von der Spezifikation: kein pysmi-Compiler (weniger Angriffsfläche, keine Abhängigkeit); Textual
Conventions und Tabellenindizes werden nicht ausgewertet.
"""

from __future__ import annotations

import io
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any

MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 200
MAX_ZIP_TOTAL = 20 * 1024 * 1024
ROOTS = {
    "iso": "1", "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
    "private": "1.3.6.1.4", "enterprises": "1.3.6.1.4.1", "snmpV2": "1.3.6.1.6", "transmission": "1.3.6.1.2.1.10",
    "experimental": "1.3.6.1.3", "directory": "1.3.6.1.1",
}
_MODULE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s+DEFINITIONS\s*::=\s*BEGIN", re.M)
_COMMENT = re.compile(r"--[^\n]*")
_DEF = re.compile(
    r"(?P<name>[a-z][A-Za-z0-9-]*)\s+(?:OBJECT\s+IDENTIFIER|OBJECT-TYPE|MODULE-IDENTITY|OBJECT-IDENTITY|NOTIFICATION-TYPE)"
    r"(?P<body>(?:(?!::=).)*?)::=\s*\{\s*(?P<parent>[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)*)?\s*(?P<rest>[\d\s]+?)\s*\}",
    re.S)
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class MibError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _text(raw: bytes) -> str:
    if b"\x00" in raw:
        raise MibError("mib_not_text")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse(text: str) -> tuple[str, list[tuple[str, str, list[int]]]]:
    """(Modulname, [(Name, Elternname-oder-OID, [Suffix…])])."""
    clean = _COMMENT.sub("", text)
    m = _MODULE.search(clean)
    if not m:
        raise MibError("mib_invalid")
    defs = []
    for d in _DEF.finditer(clean):
        parent = d.group("parent") or ""
        rest = [int(x) for x in d.group("rest").split()]
        if not parent and not rest:
            continue
        defs.append((d.group("name"), parent, rest))
    return m.group(1), defs


class Store:
    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def _index(self) -> dict[str, Any]:
        try:
            return json.loads((self.dir / "index.json").read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def modules(self) -> list[dict[str, Any]]:
        return [{"module": m, "objects": len(v["objects"]), "unresolved": v.get("unresolved", 0), "file": v["file"]}
                for m, v in sorted(self._index().items())]

    def _known(self, idx: dict[str, Any]) -> dict[str, str]:
        known = dict(ROOTS)
        for v in idx.values():
            known.update(v["objects"])
        return known

    def add(self, filename: str, raw: bytes) -> dict[str, Any]:
        if not _NAME.match(filename) or len(raw) > MAX_FILE:
            raise MibError("mib_invalid_file")
        module, defs = parse(_text(raw))
        idx = self._index()
        if len(idx) >= MAX_FILES and module not in idx:
            raise MibError("mib_too_many")
        known = self._known({k: v for k, v in idx.items() if k != module})
        objects: dict[str, str] = {}
        pending = list(defs)
        for _ in range(20):  # Abhängigkeiten innerhalb der Datei in beliebiger Reihenfolge
            left = []
            for name, parent, rest in pending:
                numeric = parent if re.fullmatch(r"\d+(\.\d+)*", parent) else None
                base = known.get(parent) or objects.get(parent) or numeric
                if parent == "" and rest:
                    base = ""
                if base is None:
                    left.append((name, parent, rest))
                    continue
                objects[name] = ".".join(x for x in [base, *map(str, rest)] if x)
            if len(left) == len(pending):
                break
            pending = left
        self.dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        (self.dir / f"{module}.mib").write_bytes(raw)
        idx[module] = {"file": filename, "objects": objects, "unresolved": len(pending)}
        tmp = self.dir / "index.tmp"
        tmp.write_text(json.dumps(idx), "utf-8")
        os.replace(tmp, self.dir / "index.json")
        return {"module": module, "objects": len(objects), "unresolved": len(pending)}

    def add_zip(self, raw: bytes) -> list[dict[str, Any]]:
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            raise MibError("mib_invalid_file") from None
        infos = [i for i in z.infolist() if not i.is_dir() and i.filename.lower().endswith((".mib", ".my", ".txt"))]
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
            raise MibError("mib_zip_too_large")
        out, errors = [], 0
        for i in infos:
            if i.file_size > MAX_FILE:
                errors += 1
                continue
            name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(i.filename).name)[:64]
            try:
                out.append(self.add(name, z.read(i)))
            except MibError:
                errors += 1
        if not out:
            raise MibError("mib_invalid")
        return out + ([{"skipped": errors}] if errors else [])

    def remove(self, module: str) -> bool:
        idx = self._index()
        if module not in idx or not _NAME.match(module):
            return False
        del idx[module]
        (self.dir / f"{module}.mib").unlink(missing_ok=True)
        (self.dir / "index.json").write_text(json.dumps(idx), "utf-8")
        return True

    def search(self, q: str, limit: int = 50) -> list[dict[str, str]]:
        q = q.lower().strip()
        out = []
        for module, v in self._index().items():
            for name, oid in v["objects"].items():
                if q in name.lower():
                    out.append({"module": module, "name": name, "oid": oid})
                    if len(out) >= limit:
                        return out
        return out

    def resolve(self, name: str) -> str | None:
        for v in self._index().values():
            if name in v["objects"]:
                return v["objects"][name]
        return None
