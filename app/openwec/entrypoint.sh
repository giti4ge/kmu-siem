#!/bin/sh
# Wartet auf Konfiguration und Keytab (werden von der Control-Plane geschrieben), initialisiert die
# Datenbank, lädt die Subscriptions und startet openwecd. Änderungen an Konfiguration oder
# Subscriptions werden automatisch übernommen (Neuladen bzw. Neustart).
set -eu

CONF=/etc/openwec/openwec.conf.toml
KEYTAB=/etc/openwec/krb5.keytab
SUBS=/etc/openwec/subscriptions

sig() { cat "$CONF" "$KEYTAB" 2>/dev/null | sha256sum | cut -d' ' -f1; }
subsig() { cat "$SUBS"/*.toml 2>/dev/null | sha256sum | cut -d' ' -f1; }

while [ ! -s "$CONF" ] || [ ! -s "$KEYTAB" ]; do
    echo "siem-openwec: warte auf Konfiguration und Keytab (Einrichtung im Web-UI: Quellen > Windows)"
    sleep 10
done

openwec db init
load_subs() {
    if ls "$SUBS"/*.toml >/dev/null 2>&1; then openwec subscriptions load "$SUBS"; fi
}
load_subs

cur=$(sig)
cursubs=$(subsig)
openwecd &
pid=$!
trap 'kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; exit 0' TERM INT

while kill -0 "$pid" 2>/dev/null; do
    sleep 5
    new=$(sig)
    if [ "$new" != "$cur" ]; then
        echo "siem-openwec: Konfiguration geändert – Neustart"
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        exec "$0"
    fi
    newsubs=$(subsig)
    if [ "$newsubs" != "$cursubs" ]; then
        echo "siem-openwec: Subscriptions geändert – neu laden"
        load_subs || echo "siem-openwec: Laden der Subscriptions fehlgeschlagen"
        kill -HUP "$pid" 2>/dev/null || true
        cursubs=$newsubs
    fi
done
wait "$pid"
