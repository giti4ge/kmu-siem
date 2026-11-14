"""Audit-Policy-Check (Spec 4.4/4.4b): Soll-Ist-Vergleich der Advanced Audit Policy je Windows-Server.

Agentlos: Ein PowerShell-Skript liest je Server per ``auditpol /backup`` (sprachunabhängig, numerische Werte)
die tatsächliche Richtlinie und erzeugt eine JSON-Datei. Diese wird im Web-UI hochgeladen und gegen die
empfohlene Richtlinie (``wec.recommended_audit_policy``) geprüft. Je Server bleibt der letzte Bericht erhalten.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import wec

MAX_SERVERS = 500
_COMPUTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_GUID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
FILE = "audit-reports.json"


def validate_upload(raw: Any) -> list[dict[str, Any]]:
    """Hochgeladene Berichte prüfen (ein Objekt oder eine Liste); alles außer erwarteten Feldern wird verworfen."""
    items = raw if isinstance(raw, list) else [raw]
    if not items or len(items) > MAX_SERVERS:
        raise wec.WecError("audit_invalid_report")
    out = []
    for it in items:
        if not isinstance(it, dict) or not _COMPUTER.match(str(it.get("computer", ""))):
            raise wec.WecError("audit_invalid_report")
        settings = it.get("settings")
        if not isinstance(settings, list) or not settings or len(settings) > 300:
            raise wec.WecError("audit_invalid_report")
        clean: dict[str, int] = {}
        for s in settings:
            guid, val = (s.get("guid"), s.get("value")) if isinstance(s, dict) else (None, None)
            if not isinstance(guid, str) or not _GUID.match(guid) or isinstance(val, bool) \
                    or not isinstance(val, int) or not 0 <= val <= 3:
                raise wec.WecError("audit_invalid_report")
            clean[guid.upper()] = val
        out.append({"computer": str(it["computer"]).lower(), "collected": str(it.get("collected", ""))[:40],
                    "settings": clean})
    return out


def evaluate(settings: dict[str, int]) -> list[dict[str, Any]]:
    """Abweichungen von der Empfehlung: fehlendes Success/Failure je Unterkategorie."""
    deviations = []
    for rec in wec.recommended_audit_policy():
        guid = rec["guid"].upper()
        want = int(rec["success"]) | (int(rec["failure"]) << 1)
        have = settings.get(guid, 0)
        missing = want & ~have
        if missing:
            deviations.append({"subcategory": rec["subcategory"], "missing_success": bool(missing & 1),
                               "missing_failure": bool(missing & 2), "configured": have})
    return deviations


def _path(wec_dir: Path) -> Path:
    return wec_dir / FILE


def load(wec_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads(_path(wec_dir).read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(wec_dir: Path, reports: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    data = load(wec_dir)
    ts = (now or datetime.now(UTC)).isoformat()
    for r in reports:
        data[r["computer"]] = {"collected": r["collected"], "uploaded": ts, "settings": r["settings"]}
    wec_dir.mkdir(parents=True, exist_ok=True)
    wec._write(_path(wec_dir), json.dumps(data), 0o640)
    return data


def view(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for computer, rep in sorted(data.items()):
        dev = evaluate({k: int(v) for k, v in rep.get("settings", {}).items()})
        rows.append({"computer": computer, "collected": rep.get("collected", ""), "uploaded": rep.get("uploaded", ""),
                     "ok": not dev, "deviations": dev})
    return rows


SCRIPT = r"""#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  KMU-SIEM – Audit-Policy-Check
  Liest die tatsächliche Advanced Audit Policy (auditpol, sprachunabhängig) und schreibt eine JSON-Datei,
  die im Web-UI unter Quellen -> Windows-Anbindung hochgeladen wird. Es werden keine Einstellungen geändert.

  Lokal:    .\siem-audit-check.ps1
  Mehrere:  .\siem-audit-check.ps1 -ComputerName srv-dc01,srv-exch01   (PowerShell-Remoting, lesender Zugriff)
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$OutFile = (Join-Path (Get-Location) 'siem-audit-check.json')
)
$ErrorActionPreference = 'Stop'

$collect = {
    $tmp = Join-Path $env:TEMP ('siem-audit-' + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        & auditpol.exe /backup /file:$tmp | Out-Null
        $rows = Get-Content -LiteralPath $tmp | ConvertFrom-Csv -Header m, t, sub, guid, incl, excl, val
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    $rows | Where-Object { $_.guid -match '^\{[0-9A-Fa-f-]{36}\}$' } | ForEach-Object {
        [pscustomobject]@{ guid = $_.guid; value = [int]$_.val }
    }
}

$reports = foreach ($c in $ComputerName) {
    Write-Host "Prüfe $c ..."
    try {
        $s = if ($c -eq $env:COMPUTERNAME) { & $collect } else { Invoke-Command -ComputerName $c -ScriptBlock $collect }
        [pscustomobject]@{
            computer  = $c
            collected = (Get-Date).ToUniversalTime().ToString('o')
            settings  = @($s | ForEach-Object { [pscustomobject]@{ guid = $_.guid; value = $_.value } })
        }
    } catch {
        Write-Warning "${c}: $($_.Exception.Message)"
    }
}
ConvertTo-Json -InputObject @($reports) -Depth 5 | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Fertig: $OutFile – im Web-UI hochladen."
"""
