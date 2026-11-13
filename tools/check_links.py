#!/usr/bin/env python3
"""Prüft relative Links und Anker in allen Markdown-Dateien des Repositories.

Aufruf: python tools/check_links.py   (Exit 1 bei defekten Links)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".vm", ".venv"}

HEADING = re.compile(r"^#+\s+(.*)$", re.MULTILINE)
CODE_BLOCK = re.compile(r"```.*?```", re.DOTALL)
LINK = re.compile(r"\]\(([^)\s]+)\)")


def slug(heading: str) -> str:
    """GitHub-kompatibler Anker zu einer Überschrift."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def markdown_files() -> list[Path]:
    return [
        p
        for p in ROOT.rglob("*.md")
        if not any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts)
    ]


def main() -> int:
    files = markdown_files()
    anchors: dict[Path, set[str]] = {}
    for f in files:
        text = CODE_BLOCK.sub("", f.read_text(encoding="utf-8"))
        anchors[f.resolve()] = {slug(h) for h in HEADING.findall(text)}

    errors = []
    for f in files:
        text = CODE_BLOCK.sub("", f.read_text(encoding="utf-8"))
        for target in LINK.findall(text):
            if re.match(r"^[a-z]+:", target):
                continue  # http:, https:, mailto: …
            path_part, _, anchor = target.partition("#")
            dest = (f.parent / path_part).resolve() if path_part else f.resolve()
            rel = f.relative_to(ROOT)
            if not dest.exists():
                errors.append(f"{rel}: Ziel fehlt: {target}")
            elif anchor and dest.is_file() and anchor not in anchors.get(dest, set()):
                errors.append(f"{rel}: Anker fehlt: {target}")

    for e in errors:
        print(e)
    print(f"{len(files)} Dateien geprüft, {len(errors)} Fehler")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
