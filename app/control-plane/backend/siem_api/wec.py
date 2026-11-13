"""Windows Event Forwarding (OpenWEC): Konfiguration, Subscriptions, Onboarding-Skript, Keytab-Prüfung.

Reine Funktionen ohne Seiteneffekte (außer ``write_all``), damit sie ohne Container testbar sind.
Die Dateien landen im gemeinsamen Verzeichnis ``wec_dir`` (siehe docker-compose: ``/data/openwec`` in
der API, ``/etc/openwec`` im Container ``siem-openwec``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import uuid
from pathlib import Path
from typing import Any

OPENWEC_PORT = 5985
VECTOR_PORT = 10600
ROLES = ("dc", "exchange", "member", "client")

_FQDN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_OU = re.compile(r"^(OU|CN|DC)=[^,\"'`$;|&<>\r\n]{1,64}(,(OU|CN|DC)=[^,\"'`$;|&<>\r\n]{1,64}){0,15}$", re.I)
_SERVICE_ACCOUNT = re.compile(r"^[A-Za-z0-9._-]{1,20}$")
_NS = uuid.UUID("6f3a3c0e-5b0e-4f55-9d0b-0b6c1f7a1d10")

DEFAULT_SETTINGS: dict[str, Any] = {
    "domain": "",
    "fqdn": "",
    "service_account": "svc-siem-wec",
    "roles": {r: [] for r in ROLES},
}


class WecError(ValueError):
    """Ungültige Eingabe; ``code`` ist ein API-Fehlercode (für die Übersetzung im UI)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_settings(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WecError("wec_invalid_settings")
    domain = str(raw.get("domain", "")).strip().lower().rstrip(".")
    fqdn = str(raw.get("fqdn", "")).strip().lower().rstrip(".")
    account = str(raw.get("service_account", DEFAULT_SETTINGS["service_account"])).strip()
    if not _DOMAIN.match(domain):
        raise WecError("wec_invalid_domain")
    if not _FQDN.match(fqdn):
        raise WecError("wec_invalid_fqdn")
    if not _SERVICE_ACCOUNT.match(account):
        raise WecError("wec_invalid_account")
    roles_in = raw.get("roles", {})
    if not isinstance(roles_in, dict) or set(roles_in) - set(ROLES):
        raise WecError("wec_invalid_roles")
    roles: dict[str, list[str]] = {}
    for role in ROLES:
        ous = roles_in.get(role, [])
        if not isinstance(ous, list) or len(ous) > 50:
            raise WecError("wec_invalid_ou")
        clean: list[str] = []
        for ou in ous:
            ou = str(ou).strip()
            if not _OU.match(ou):
                raise WecError("wec_invalid_ou")
            if ou not in clean:
                clean.append(ou)
        roles[role] = clean
    return {"domain": domain, "fqdn": fqdn, "service_account": account, "roles": roles}


def realm(settings: dict[str, Any]) -> str:
    return str(settings["domain"]).upper()


def principal(settings: dict[str, Any]) -> str:
    return f"HTTP/{settings['fqdn']}@{realm(settings)}"


# --- OpenWEC-Serverkonfiguration -------------------------------------------------------------

def render_conf(settings: dict[str, Any]) -> str:
    return f"""# Von der KMU-SIEM Control-Plane erzeugt – nicht von Hand ändern
[server]
keytab = "/etc/openwec/krb5.keytab"
db_sync_interval = 5

[logging]
verbosity = "info"
server_logs = "stderr"

[database]
type = "SQLite"
path = "/var/db/openwec/openwec.sqlite"

[[collectors]]
hostname = "{settings['fqdn']}"
listen_address = "0.0.0.0"
listen_port = {OPENWEC_PORT}

[collectors.authentication]
type = "Kerberos"
service_principal_name = "{principal(settings)}"

[cli]
read_only_subscriptions = true
"""


# --- Subscriptions (Rollen) ----------------------------------------------------------------------

def _ids(ids: list[int]) -> str:
    return " or ".join(f"EventID={i}" for i in ids)


def _select(path: str, xpath: str) -> str:
    return f'    <Select Path="{path}">{xpath}</Select>'


def _security(ids: list[int]) -> list[str]:
    # Windows begrenzt XPath-Ereignisabfragen (max. 22 Ausdrücke): in Gruppen aufteilen
    out = []
    for i in range(0, len(ids), 15):
        out.append(_select("Security", f"*[System[({_ids(ids[i:i + 15])})]]"))
    return out


def _level(path: str, max_level: int = 3) -> str:
    return _select(path, f"*[System[(Level &gt;= 1 and Level &lt;= {max_level})]]")


_LOGON = [4624, 4625, 4634, 4647, 4648, 4672, 4740, 4767]
_IAM = [4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737,
        4738, 4741, 4743, 4754, 4755, 4756, 4757, 4758]
_CONFIG = [4697, 4698, 4699, 4700, 4701, 4702, 4719, 1102]
_FIM = [4663, 4660, 4670, 5145]
_DEFENDER = [1116, 1117, 1118, 1119, 5001, 5007]


def _defender() -> str:
    return _select("Microsoft-Windows-Windows Defender/Operational", f"*[System[({_ids(_DEFENDER)})]]")


def role_queries(role: str) -> list[str]:
    if role == "dc":
        sel = _security(_LOGON + [4768, 4769, 4771, 4776, 4794] + _IAM + _CONFIG
                        + [5136, 5137, 5139, 5141])
        sel += [_level("Directory Service"), _level("DNS Server"),
                _select("System", "*[System[(Level &gt;= 1 and Level &lt;= 2) or (EventID=104)]]")]
    elif role == "exchange":
        sel = [_level("MSExchange Management", 4), _select("Application", "*[System[Provider[starts-with(@Name,'MSExchange')] and (Level &gt;= 1 and Level &lt;= 3)]]")]
        sel += _security([4624, 4625, 4648, 4672] + _CONFIG)
        sel += [_select("System", "*[System[(Level &gt;= 1 and Level &lt;= 2) or (EventID=7045) or (EventID=104)]]")]
    elif role == "member":
        sel = _security(_LOGON[:6] + [4688] + _IAM[:12] + _CONFIG + _FIM)
        sel += [_select("System", "*[System[(Level &gt;= 1 and Level &lt;= 2) or (EventID=7045) or (EventID=104)]]"),
                _select("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]"),
                _defender()]
    elif role == "client":
        sel = _security([4625, 4672, 4720, 4722, 4724, 4725, 4726, 4732, 4733, 6416])
        sel += [_select("System", "*[System[(EventID=7045)]]"), _defender()]
    else:
        raise WecError("wec_invalid_roles")
    return sel


def role_query(role: str) -> str:
    return '<QueryList>\n  <Query Id="0">\n' + "\n".join(role_queries(role)) + "\n  </Query>\n</QueryList>"


def role_uri(role: str) -> str:
    return f"/wec/{role}"


def render_subscription(role: str) -> str:
    uid = uuid.uuid5(_NS, f"siem-{role}")
    return f'''uuid = "{uid}"
name = "siem-{role}"
query = """
{role_query(role)}
"""

[options]
enabled = true
uri = "{role_uri(role)}"
heartbeat_interval = 900
max_time = 30
content_format = "Raw"

[[outputs]]
driver = "Tcp"
format = "Json"
config = {{ host = "127.0.0.1", port = {VECTOR_PORT} }}
'''


def active_roles(settings: dict[str, Any]) -> list[str]:
    return [r for r in ROLES if settings["roles"].get(r)]


# --- Onboarding-Skript (PowerShell) -----------------------------------------------------------------

_AUDIT_SUBCATEGORIES = {
    # Name: (GUID, Success, Failure)
    "Credential Validation": ("0CCE923F", 1, 1),
    "Kerberos Authentication Service": ("0CCE9242", 1, 1),
    "Kerberos Service Ticket Operations": ("0CCE9240", 1, 1),
    "Computer Account Management": ("0CCE9236", 1, 0),
    "Other Account Management Events": ("0CCE923A", 1, 0),
    "Security Group Management": ("0CCE9237", 1, 0),
    "User Account Management": ("0CCE9235", 1, 1),
    "Process Creation": ("0CCE922B", 1, 0),
    "Directory Service Access": ("0CCE923B", 0, 1),
    "Directory Service Changes": ("0CCE923C", 1, 0),
    "Logon": ("0CCE9215", 1, 1),
    "Logoff": ("0CCE9216", 1, 0),
    "Account Lockout": ("0CCE9217", 0, 1),
    "Special Logon": ("0CCE921B", 1, 0),
    "File System": ("0CCE921D", 1, 1),
    "File Share": ("0CCE9224", 1, 1),
    "Detailed File Share": ("0CCE9244", 0, 1),
    "Other Object Access Events": ("0CCE9227", 1, 1),
    "Removable Storage": ("0CCE9245", 1, 1),
    "Audit Policy Change": ("0CCE922F", 1, 1),
    "Authentication Policy Change": ("0CCE9230", 1, 0),
    "Security System Extension": ("0CCE9211", 1, 0),
    "Plug and Play Events": ("0CCE9248", 1, 0),
}


def audit_csv_lines() -> list[str]:
    """Empfohlene Advanced Audit Policy als audit.csv-Zeilen (Inhalt für die GPO)."""
    lines = []
    for name, (guid, ok, fail) in _AUDIT_SUBCATEGORIES.items():
        value = ok | (fail << 1)
        text = {1: "Success", 2: "Failure", 3: "Success and Failure"}[value]
        lines.append(f",System,Audit {name},{{{guid}-69AE-11D9-BED3-505054503030}},{text},,{value}")
    return lines


def recommended_audit_policy() -> list[dict[str, Any]]:
    return [{"subcategory": n, "guid": f"{{{g}-69AE-11D9-BED3-505054503030}}", "success": bool(s), "failure": bool(f)}
            for n, (g, s, f) in _AUDIT_SUBCATEGORIES.items()]


def _ps(value: str) -> str:
    """Zeichenkette als PowerShell-Literal in einfachen Anführungszeichen."""
    return "'" + value.replace("'", "''") + "'"


def render_script(settings: dict[str, Any]) -> str:
    """PowerShell-Onboarding-Skript (Domain-Admin): Dienstkonto, SPN, Keytab, GPOs je Rolle."""
    roles = {r: settings["roles"].get(r, []) for r in ROLES}
    role_lines = "\n".join(
        f"    {r} = @({', '.join(_ps(o) for o in ous)})" for r, ous in roles.items())
    audit_rows = "\n".join(f"    {_ps(line)}" for line in audit_csv_lines())
    return _SCRIPT_TEMPLATE.replace("@@DOMAIN@@", _ps(settings["domain"])) \
        .replace("@@REALM@@", _ps(realm(settings))) \
        .replace("@@FQDN@@", _ps(settings["fqdn"])) \
        .replace("@@ACCOUNT@@", _ps(settings["service_account"])) \
        .replace("@@PORT@@", str(OPENWEC_PORT)) \
        .replace("@@ROLES@@", role_lines) \
        .replace("@@AUDIT@@", audit_rows)


def script_sha256(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


_SCRIPT_TEMPLATE = r"""#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  KMU-SIEM – Windows-Onboarding (Event Forwarding)
  Auszuführen von einem Domain-Administrator auf einem Domänencontroller oder einer Verwaltungsstation
  mit RSAT (ActiveDirectory- und GroupPolicy-Modul). Das Skript
    1. legt das Dienstkonto an (Kerberos AES256, Kennwort zufällig, läuft nicht ab),
    2. setzt den SPN HTTP/<Appliance-FQDN> und erzeugt die Keytab (siem-wec.keytab),
    3. legt je Rolle eine GPO "SIEM Event Forwarding - <Rolle>" an und verknüpft sie mit den OUs:
       Subscription Manager, WinRM, Leserechte auf das Security-Log, empfohlene Audit-Richtlinie,
       Prozess-Kommandozeile (4688), PowerShell-Script-Block-Logging,
    4. prüft die Voraussetzungen und gibt einen Bericht aus.
  Mehrfaches Ausführen ist unbedenklich (idempotent). Die Keytab anschließend im Web-UI hochladen.
  Prüfsumme dieses Skripts: im Web-UI angezeigt (Get-FileHash -Algorithm SHA256).
#>
[CmdletBinding()]
param(
    [string]$KeytabPath = (Join-Path $PWD 'siem-wec.keytab')
)
$ErrorActionPreference = 'Stop'

$Domain    = @@DOMAIN@@
$Realm     = @@REALM@@
$Fqdn      = @@FQDN@@
$Account   = @@ACCOUNT@@
$Port      = @@PORT@@
$Roles = [ordered]@{
@@ROLES@@
}
$RoleNames = @{ dc = 'Domänencontroller'; exchange = 'Exchange'; member = 'Mitgliedsserver'; client = 'Clients' }
$AuditRows = @(
@@AUDIT@@
)

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "    !!  $m" -ForegroundColor Yellow }

Write-Step 'Voraussetzungen'
foreach ($mod in 'ActiveDirectory', 'GroupPolicy') {
    if (-not (Get-Module -ListAvailable -Name $mod)) { throw "PowerShell-Modul $mod fehlt (RSAT installieren)." }
    Import-Module $mod
}
$adDomain = Get-ADDomain
if ($adDomain.DNSRoot -ne $Domain) { Write-Warn2 "Domäne des Skripts ($Domain) weicht von der aktuellen ($($adDomain.DNSRoot)) ab." }
Write-Ok "Domäne $($adDomain.DNSRoot)"
try { [void][System.Net.Dns]::GetHostAddresses($Fqdn); Write-Ok "DNS: $Fqdn auflösbar" }
catch { Write-Warn2 "DNS: $Fqdn nicht auflösbar - A-Record für die Appliance anlegen." }

Write-Step "Dienstkonto $Account"
$pwChars = (48..57) + (65..90) + (97..122)
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plain = -join ($bytes | ForEach-Object { [char]$pwChars[$_ % $pwChars.Count] })
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
$user = Get-ADUser -Filter "SamAccountName -eq '$Account'" -ErrorAction SilentlyContinue
if (-not $user) {
    New-ADUser -Name $Account -SamAccountName $Account -AccountPassword $secure -Enabled $true `
        -PasswordNeverExpires $true -CannotChangePassword $true -Description 'KMU-SIEM Windows Event Forwarding' `
        -KerberosEncryptionType AES256
    Write-Ok 'Konto angelegt'
} else {
    Set-ADAccountPassword -Identity $Account -Reset -NewPassword $secure
    Set-ADUser -Identity $Account -PasswordNeverExpires $true -KerberosEncryptionType AES256
    Write-Ok 'Konto vorhanden - Kennwort neu gesetzt'
}

Write-Step "SPN HTTP/$Fqdn"
$existing = & setspn.exe -Q "HTTP/$Fqdn" 2>&1 | Out-String
if ($existing -match [regex]::Escape($Account)) { Write-Ok 'SPN bereits dem Dienstkonto zugeordnet' }
elseif ($existing -match 'Existing SPN found|Bestehender SPN') { throw "SPN HTTP/$Fqdn ist bereits einem anderen Konto zugeordnet." }
else { & setspn.exe -S "HTTP/$Fqdn" $Account | Out-Null; Write-Ok 'SPN gesetzt' }

Write-Step "Keytab $KeytabPath"
& ktpass.exe -princ "HTTP/$Fqdn@$Realm" -mapuser "$($adDomain.NetBIOSName)\$Account" -pass $plain `
    -ptype KRB5_NT_PRINCIPAL -crypto AES256-SHA1 -out $KeytabPath | Out-Null
if (-not (Test-Path $KeytabPath)) { throw 'Keytab wurde nicht erzeugt (ktpass).' }
Write-Ok "Keytab erzeugt - im Web-UI hochladen, danach Datei löschen"
$plain = $null

$policyKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog'
$smValue     = "Server=http://${Fqdn}:$Port"
$sddlSecurity = 'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)'

foreach ($role in $Roles.Keys) {
    $ous = @($Roles[$role])
    if ($ous.Count -eq 0) { continue }
    $gpoName = "SIEM Event Forwarding - $($RoleNames[$role])"
    Write-Step "GPO '$gpoName'"
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $gpoName -Comment 'KMU-SIEM (automatisch erzeugt)'; Write-Ok 'angelegt' } else { Write-Ok 'vorhanden - wird aktualisiert' }

    # Subscription Manager (rollenspezifische URL) + WinRM-Dienst
    Set-GPRegistryValue -Name $gpoName -Key "$policyKey\EventForwarding\SubscriptionManager" -ValueName '1' `
        -Type String -Value "$smValue/wec/$role,Refresh=60" | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' -ValueName 'Start' `
        -Type DWord -Value 2 | Out-Null
    # Leserechte auf das Security-Log für NETWORK SERVICE
    Set-GPRegistryValue -Name $gpoName -Key "$policyKey\Security" -ValueName 'CustomSD' -Type String -Value $sddlSecurity | Out-Null
    # Prozess-Kommandozeile in 4688, PowerShell-Script-Block-Logging (4104)
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 | Out-Null
    # Erweiterte Audit-Richtlinie statt Legacy-Einstellungen
    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'SCENoApplyLegacyAuditPolicy' `
        -Type DWord -Value 1 | Out-Null

    # audit.csv in SYSVOL (Advanced Audit Policy) + Client-Side-Extension eintragen
    $gpoPath = "\\$($adDomain.DNSRoot)\SYSVOL\$($adDomain.DNSRoot)\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\Audit"
    New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    Set-Content -Path (Join-Path $gpoPath 'audit.csv') -Value (@($header) + $AuditRows) -Encoding Unicode
    $gpoDn = "CN={$($gpo.Id)},CN=Policies,CN=System,$($adDomain.DistinguishedName)"
    $ext = (Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
    $auditExt = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    if (-not $ext -or $ext -notlike "*F3CCC681-B74C-4060-9F26-CD84525DCA2A*") {
        Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = "$ext$auditExt" }
    }
    # Gruppenmitgliedschaft: NETWORK SERVICE in "Ereignisprotokollleser" (S-1-5-32-573)
    $secPath = "\\$($adDomain.DNSRoot)\SYSVOL\$($adDomain.DNSRoot)\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit"
    New-Item -ItemType Directory -Path $secPath -Force | Out-Null
    $inf = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n[Group Membership]`r`n*S-1-5-32-573__Memberof =`r`n*S-1-5-32-573__Members = *S-1-5-20`r`n"
    Set-Content -Path (Join-Path $secPath 'GptTmpl.inf') -Value $inf -Encoding Unicode
    $ext = (Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
    $secExt = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    if ($ext -notlike '*827D319E-6EAC-11D2-A4EA-00C04F79F83A*') {
        Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = "$ext$secExt" }
    }

    foreach ($ou in $ous) {
        try {
            New-GPLink -Name $gpoName -Target $ou -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Ok "verknüpft mit $ou"
        } catch {
            if ($_.Exception.Message -match 'already linked|bereits') { Write-Ok "bereits verknüpft mit $ou" }
            else { Write-Warn2 "Verknüpfung mit $ou fehlgeschlagen: $($_.Exception.Message)" }
        }
    }
}

Write-Step 'Fertig'
Write-Host "Nächste Schritte:" -ForegroundColor White
Write-Host "  1. Keytab '$KeytabPath' im SIEM-Web-UI (Quellen > Windows) hochladen und danach löschen."
Write-Host "  2. 'gpupdate /force' auf einem Zielserver ausführen (oder bis zu 90 Minuten warten)."
Write-Host "  3. Der Server sendet danach Ereignisse (Index siem-windows).."
"""


# --- Keytab ------------------------------------------------------------------------------------------

def keytab_principals(data: bytes) -> list[tuple[str, str]]:
    """(Prinzipal, Realm) aller Einträge einer MIT-Keytab (Format 0x0502); ``WecError`` bei Fehlern."""
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x02:
        raise WecError("wec_keytab_invalid")
    pos = 2
    found: list[tuple[str, str]] = []
    try:
        while pos + 4 <= len(data):
            (size,) = struct.unpack_from(">i", data, pos)
            pos += 4
            if size < 0:           # gelöschter Eintrag
                pos += -size
                continue
            end = pos + size
            (ncomp,) = struct.unpack_from(">h", data, pos)
            p = pos + 2
            (rlen,) = struct.unpack_from(">h", data, p)
            p += 2
            rlm = data[p:p + rlen].decode("utf-8")
            p += rlen
            comps = []
            for _ in range(ncomp):
                (clen,) = struct.unpack_from(">h", data, p)
                p += 2
                comps.append(data[p:p + clen].decode("utf-8"))
                p += clen
            found.append(("/".join(comps), rlm))
            pos = end
    except (struct.error, UnicodeDecodeError) as exc:
        raise WecError("wec_keytab_invalid") from exc
    if not found:
        raise WecError("wec_keytab_invalid")
    return found


def check_keytab(data: bytes, settings: dict[str, Any]) -> None:
    want = (f"HTTP/{settings['fqdn']}", realm(settings))
    if want not in [(p, r.upper()) for p, r in keytab_principals(data)]:
        raise WecError("wec_keytab_principal")


# --- Dateien / Status -----------------------------------------------------------------------------------

def _write(path: Path, data: str | bytes, mode: int = 0o640) -> None:
    tmp = path.with_name(path.name + ".tmp")
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def settings_path(wec_dir: Path) -> Path:
    return wec_dir / "settings.json"


def load_settings(wec_dir: Path) -> dict[str, Any]:
    try:
        return validate_settings(json.loads(settings_path(wec_dir).read_text("utf-8")))
    except (OSError, ValueError, WecError):
        return json.loads(json.dumps(DEFAULT_SETTINGS))


def write_all(wec_dir: Path, settings: dict[str, Any]) -> None:
    """Konfiguration und Subscriptions schreiben (Container übernimmt Änderungen automatisch)."""
    wec_dir.mkdir(parents=True, exist_ok=True)
    subs = wec_dir / "subscriptions"
    subs.mkdir(exist_ok=True)
    os.chmod(subs, 0o750)  # noqa: S103 – Gruppe siem-api liest
    wanted = set()
    for role in active_roles(settings):
        name = f"siem-{role}.toml"
        wanted.add(name)
        _write(subs / name, render_subscription(role))
    for old in subs.glob("siem-*.toml"):
        if old.name not in wanted:
            old.unlink()
    _write(wec_dir / "openwec.conf.toml", render_conf(settings))
    _write(settings_path(wec_dir), json.dumps(settings, indent=2))


def keytab_present(wec_dir: Path) -> bool:
    p = wec_dir / "krb5.keytab"
    return p.is_file() and p.stat().st_size > 0
