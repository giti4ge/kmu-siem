#!/bin/sh
# KMU-SIEM Support-Shell: einzige erlaubte Befehle für den Benutzer siem-support (sshd ForceCommand).
# Keine Shell, keine freien Befehle, kein Zugriff auf Ereignisdaten (OpenSearch).
set -eu
cmd=${SSH_ORIGINAL_COMMAND:-help}
logger -t siem-support "Befehl: $cmd"
# shellcheck disable=SC2086
set -- $cmd
case "${1:-help}" in
  status)
    exec /usr/local/sbin/siem-hostd system status ;;
  logs)
    src=${2:-install}
    lines=${3:-200}
    case "$lines" in ''|*[!0-9]*) echo "Zeilenzahl ungültig" >&2; exit 2 ;; esac
    [ "$lines" -le 1000 ] || lines=1000
    exec /usr/local/sbin/siem-hostd system logs --source "$src" --lines "$lines" ;;
  containers)
    exec /usr/bin/docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' ;;
  version)
    cat /opt/siem/VERSION 2>/dev/null || echo unbekannt ;;
  *)
    echo "Erlaubte Befehle: status | logs <quelle> [zeilen] | containers | version" ;;
esac
