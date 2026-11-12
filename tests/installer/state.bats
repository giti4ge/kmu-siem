#!/usr/bin/env bats
# Installationszustand und Schrittsteuerung

setup() {
    source "$BATS_TEST_DIRNAME/helpers.bash"
    load_libs
}

@test "Zustand: leer, setzen, ueberschreiben" {
    ! state_exists
    [ -z "$(state_get base)" ]
    state_set base running
    [ "$(state_get base)" = running ]
    state_set base done
    [ "$(state_get base)" = done ]
    state_is_done base
    [ "$(grep -c '^base ' "$(state_file)")" -eq 1 ]
    state_exists
}

@test "Zustand: Installation vollstaendig erst nach selftest" {
    state_set base done
    ! state_install_complete
    state_set selftest done
    state_install_complete
}

@test "Schritte: erledigte werden uebersprungen, erster offener endet mit 'nicht implementiert'" {
    state_set base done
    run run_steps
    [ "$status" -eq 3 ]
    [[ "$output" == *"Schritt base bereits erledigt"* ]]
    [[ "$output" == *"'datadisk' ist noch nicht implementiert"* ]]
    [ "$(state_get datadisk)" = pending ]
    [ -z "$(state_get hardening)" ]
}

@test "Schritte: implementierter Schritt wird als done vermerkt, Fehler als failed" {
    step_base() { return 0; }
    step_datadisk() { return 7; }
    run run_steps
    [ "$status" -eq 7 ]
    [ "$(state_get base)" = done ]
    [ "$(state_get datadisk)" = failed ]
}

@test "Resume: nach Fehler wird am fehlgeschlagenen Schritt fortgesetzt" {
    step_base() { return 0; }
    step_datadisk() { return 7; }
    run run_steps
    step_base() { echo "base erneut ausgeführt"; return 0; }
    step_datadisk() { return 0; }
    run run_steps
    [[ "$output" != *"base erneut ausgeführt"* ]]
    [ "$(state_get datadisk)" = done ]
}

@test "Alle Schritte haben Name, Beschreibung und Phase" {
    for i in "${!STEPS[@]}"; do
        [ -n "$(step_name "$i")" ]
        [ -n "$(step_desc "$i")" ]
        [ -n "$(step_phase "$i")" ]
    done
    [ "$(step_name 0)" = base ]
    [ "$(step_name $(( ${#STEPS[@]} - 1 )))" = selftest ]
}
