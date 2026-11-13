#!/usr/bin/env bash
# Integrationstest: install.sh --preflight in einem Debian-13-Container (als root).
#
# Prüft:
#   - echte Probes laufen unter Debian 13 fehlerfrei
#   - erwartete Ergebnisse (OS ok, systemd fehlt im Container → Exit 2)
#   - --preflight verändert das System nicht (außer dem Installationsprotokoll)
#
# Aufruf (im Container, Repository als aktuelles Verzeichnis):
#   tests/integration/preflight-container.sh
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
fail() { echo "FEHLER: $*" >&2; exit 1; }
pass() { echo "OK: $*"; }

[[ $(id -u) -eq 0 ]] || fail "muss als root laufen"
grep -q '^VERSION_ID="13"' /etc/os-release || fail "kein Debian 13"

# Zustand vor dem Lauf
marker=$(mktemp)
sleep 1
pkgs_before=$(dpkg-query -W -f='${Package} ${Version}\n' | sha256sum)

set +e
out=$(NO_COLOR=1 bash "$REPO/host/install.sh" --preflight 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
echo "Exit-Code: $rc"

# --- Erwartete Ergebnisse ----------------------------------------------------
[[ $rc -eq 2 ]] || fail "Exit-Code 2 erwartet (kein systemd im Container), erhalten: $rc"
grep -q '✔ Betriebssystem' <<<"$out" || fail "Betriebssystem nicht als OK erkannt"
grep -q '✔ Root-Rechte' <<<"$out" || fail "Root nicht erkannt"
grep -q '✘ systemd' <<<"$out" || fail "fehlendes systemd nicht erkannt"
grep -q '✔ Internet: Debian ' <<<"$out" || fail "Internet-Prüfung (Debian) nicht OK"
grep -q '✔ Internet: GitHub API' <<<"$out" || fail "Internet-Prüfung (GitHub) nicht OK"
grep -q 'Container-Laufzeit' <<<"$out" || fail "Prüfung Container-Laufzeit fehlt"
pass "erwartete Prüfergebnisse"

# Englisch
out_en=$(NO_COLOR=1 bash "$REPO/host/install.sh" --preflight --lang en 2>&1 || true)
grep -q '✔ Operating system' <<<"$out_en" || fail "englische Ausgabe fehlt"
pass "englische Ausgabe"

# Nicht erreichbarer Proxy → Internet-Prüfungen schlagen fehl
out_px=$(NO_COLOR=1 SIEM_NET_TIMEOUT=3 bash "$REPO/host/install.sh" --preflight --proxy http://127.0.0.1:9 2>&1 || true)
grep -q '✘ Internet: Debian .*nicht erreichbar (über Proxy)' <<<"$out_px" \
    || fail "nicht erreichbarer Proxy wird nicht erkannt"
pass "Proxy-Fehler erkannt"

# --- Keine Änderungen am System ----------------------------------------------
changed=$(find / -xdev -type f -newer "$marker" \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/tmp/*' ! -path '/run/*' \
    ! -path "$REPO/*" ! -path '/var/log/siem-install.log' ! -path '/__w/*' ! -path '/__e/*' \
    ! -path '/github/*' 2>/dev/null || true)
[[ -z $changed ]] || fail "Preflight hat Dateien verändert:\n$changed"
[[ ! -e /var/lib/siem ]] || fail "Preflight hat /var/lib/siem angelegt"
[[ ! -e /opt/siem ]] || fail "Preflight hat /opt/siem angelegt"
pkgs_after=$(dpkg-query -W -f='${Package} ${Version}\n' | sha256sum)
[[ $pkgs_before == "$pkgs_after" ]] || fail "Paketliste hat sich verändert"
grep -q 'PREFLIGHT' /var/log/siem-install.log || fail "kein Protokolleintrag"
pass "System unverändert (nur Protokoll geschrieben)"

echo "Alle Integrationstests bestanden."
