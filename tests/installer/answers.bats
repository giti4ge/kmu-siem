#!/usr/bin/env bats
# Antwortdatei: Parser, Sicherheit, Pflichtangaben, Geheimnisse

setup() {
    source "$BATS_TEST_DIRNAME/helpers.bash"
    load_libs
    ANSWERS=()
    F="$BATS_TEST_TMPDIR/antworten.env"
}

@test "Parser: Werte, Anfuehrungszeichen, Kommentare, leere Zeilen" {
    cat >"$F" <<'EOF'
# Kommentar
SIEM_LANG=en

SIEM_FQDN="siem.firma.local"
SIEM_NTP='dc01.firma.local,dc02.firma.local'
SIEM_PROXY=http://proxy:3128   # Kommentar am Zeilenende
SIEM_TRUNK_VLANS="10,20 # kein Kommentar in Anführungszeichen"
EOF
    parse_answer_file "$F"
    [ "${ANSWERS[SIEM_LANG]}" = en ]
    [ "${ANSWERS[SIEM_FQDN]}" = siem.firma.local ]
    [ "${ANSWERS[SIEM_NTP]}" = dc01.firma.local,dc02.firma.local ]
    [ "${ANSWERS[SIEM_PROXY]}" = http://proxy:3128 ]
    [ "${ANSWERS[SIEM_TRUNK_VLANS]}" = "10,20 # kein Kommentar in Anführungszeichen" ]
}

@test "Parser: Windows-Zeilenenden (CRLF)" {
    printf 'SIEM_FQDN=siem.firma.local\r\nSIEM_LANG=de\r\n' >"$F"
    parse_answer_file "$F"
    [ "${ANSWERS[SIEM_FQDN]}" = siem.firma.local ]
    [ "${ANSWERS[SIEM_LANG]}" = de ]
}

@test "Sicherheit: Werte werden nie ausgefuehrt" {
    marker="$BATS_TEST_TMPDIR/pwned"
    cat >"$F" <<EOF
SIEM_FQDN=\$(touch $marker)
SIEM_NTP=\`touch $marker\`
SIEM_PROXY="\$(touch $marker)"
EOF
    parse_answer_file "$F"
    [ ! -e "$marker" ]
    [ "${ANSWERS[SIEM_FQDN]}" = "\$(touch $marker)" ]
    ! valid_fqdn "${ANSWERS[SIEM_FQDN]}"
}

@test "Sicherheit: unbekannte Schluessel werden abgelehnt" {
    printf 'SIEM_FQDN=siem.firma.local\nPATH=/tmp/evil\nLD_PRELOAD=/tmp/x.so\n' >"$F"
    run parse_answer_file "$F"
    [ "$status" -eq 2 ]
    [[ "$output" == *"unbekannter Schlüssel PATH"* ]]
    [[ "$output" == *"LD_PRELOAD"* ]]
}

@test "Ungueltiges Zeilenformat wird gemeldet" {
    printf 'SIEM_FQDN siem.firma.local\nexport SIEM_LANG=de\n' >"$F"
    run parse_answer_file "$F"
    [ "$status" -eq 2 ]
    [[ "$output" == *"Zeile 1"* ]]
    [[ "$output" == *"Zeile 2"* ]]
}

@test "Fehlende Datei" {
    run parse_answer_file "$BATS_TEST_TMPDIR/gibtsnicht.env"
    [ "$status" -eq 2 ]
}

@test "Pflichtangaben und Disk-Bestaetigung" {
    ANSWERS=([SIEM_FQDN]=siem.firma.local [SIEM_NTP]=dc01 [SIEM_DATA_DISK]=/dev/sdb)
    run check_required_answers
    [ "$status" -eq 2 ]
    [[ "$output" == *"SIEM_DATA_DISK_CONFIRM=yes"* ]]

    ANSWERS[SIEM_DATA_DISK_CONFIRM]=yes
    check_required_answers

    ANSWERS=([SIEM_FQDN]=siem.firma.local [SIEM_NTP]=dc01 [SIEM_DATA_DISK]=none)
    check_required_answers

    ANSWERS=([SIEM_NTP]=dc01 [SIEM_DATA_DISK]=none)
    run check_required_answers
    [ "$status" -eq 2 ]
    [[ "$output" == *"SIEM_FQDN"* ]]
}

@test "Geheimnisse: aus Datei bevorzugt, Klartext mit Warnung" {
    printf 'GeheimesKennwort123\n' >"$BATS_TEST_TMPDIR/pw"
    ANSWERS=([SIEM_ADMIN_PASSWORD_FILE]="$BATS_TEST_TMPDIR/pw" [SIEM_ADMIN_PASSWORD]=klartext)
    run read_secret_answer SIEM_ADMIN_PASSWORD
    [ "$status" -eq 0 ]
    [ "$output" = GeheimesKennwort123 ]

    ANSWERS=([SIEM_ADMIN_PASSWORD]=KlartextKennwort1)
    run read_secret_answer SIEM_ADMIN_PASSWORD
    [ "$status" -eq 0 ]
    [[ "$output" == *"Klartext-Geheimnis"* ]]
    [[ "$output" == *"KlartextKennwort1"* ]]

    ANSWERS=()
    run read_secret_answer SIEM_ADMIN_PASSWORD
    [ "$status" -eq 1 ]
}

@test "Speichern: nur nicht geheime Werte, Rechte 0600, wieder ladbar" {
    ANSWERS=([SIEM_FQDN]=siem.firma.local [SIEM_NTP]=dc01 [SIEM_DATA_DISK]=/dev/sdb
             [SIEM_ADMIN_PASSWORD]=Geheim123456789)
    save_answers
    f="$SIEM_STATE_DIR/answers.env"
    [ -f "$f" ]
    ! grep -q Geheim "$f"
    if [[ "$(uname -s)" == Linux ]]; then
        [ "$(stat -c %a "$f")" = 600 ]
    fi
    ANSWERS=()
    load_answers
    [ "${ANSWERS[SIEM_FQDN]}" = siem.firma.local ]
    [ "${ANSWERS[SIEM_DATA_DISK]}" = /dev/sdb ]
}

@test "Geheimnis ablegen: eigenes Verzeichnis, Inhalt exakt" {
    save_secret web_admin_password 'Mein Kennwort 123'
    [ "$(cat "$SIEM_STATE_DIR/secrets/web_admin_password")" = 'Mein Kennwort 123' ]
}
