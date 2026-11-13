#!/usr/bin/env bats
# Kommandozeile von install.sh

setup() {
    source "$BATS_TEST_DIRNAME/helpers.bash"
    export NO_COLOR=1
    export SIEM_LOG_FILE="$BATS_TEST_TMPDIR/install.log"
    export SIEM_STATE_DIR="$BATS_TEST_TMPDIR/state"
    INSTALL="$HOST_DIR/install.sh"
}

@test "--help: Exit 0, beschreibt alle Betriebsarten" {
    run bash "$INSTALL" --help
    [ "$status" -eq 0 ]
    for opt in --preflight --unattended --resume --repair --proxy --proxy-ca --token-file --lang; do
        [[ "$output" == *"$opt"* ]]
    done
}

@test "--help --lang en: englisch" {
    run bash "$INSTALL" --lang en --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "--version zeigt Version aus VERSION" {
    run bash "$INSTALL" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"$(cat "$REPO_ROOT/VERSION")"* ]]
}

@test "Unbekannte Option: Exit 64" {
    run bash "$INSTALL" --gibtsnicht
    [ "$status" -eq 64 ]
    [[ "$output" == *"Unbekannte Option"* ]]
}

@test "Fehlender Wert: Exit 64" {
    run bash "$INSTALL" --unattended
    [ "$status" -eq 64 ]
    run bash "$INSTALL" --proxy
    [ "$status" -eq 64 ]
}

@test "Ungueltiger Proxy: Exit 64" {
    run bash "$INSTALL" --proxy 'kein-proxy'
    [ "$status" -eq 64 ]
}

@test "Sich ausschliessende Betriebsarten: Exit 64" {
    run bash "$INSTALL" --preflight --resume
    [ "$status" -eq 64 ]
    run bash "$INSTALL" --repair --unattended x.env
    [ "$status" -eq 64 ]
}

@test "Installation ohne root wird abgelehnt" {
    [[ ${EUID:-$(id -u)} -ne 0 ]] || skip "läuft als root"
    run bash "$INSTALL" --unattended /dev/null
    [ "$status" -eq 2 ]
    [[ "$output" == *"Root-Rechte"* ]]
}

@test "Entwicklungsstand wird angezeigt" {
    run bash "$INSTALL" --preflight
    [[ "$output" == *"Entwicklungsstand Phase 0"* ]]
}
