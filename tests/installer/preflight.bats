#!/usr/bin/env bats
# Preflight-Logik mit simulierten Systemzuständen (probe_* werden ersetzt)

setup() {
    source "$BATS_TEST_DIRNAME/helpers.bash"
    load_libs
    mock_good_system
}

@test "Gutes System: alle Pruefungen OK, Exit 0" {
    run run_preflight
    [ "$status" -eq 0 ]
    [[ "$output" == *"Alle Voraussetzungen erfüllt"* ]]
    [[ "$output" != *"✘"* ]]
}

@test "Falsches Betriebssystem -> Fehler" {
    probe_os() { printf 'debian|12|Debian GNU/Linux 12 (bookworm)'; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"Debian GNU/Linux 12"* ]]
}

@test "Ubuntu -> Fehler" {
    probe_os() { printf 'ubuntu|24.04|Ubuntu 24.04 LTS'; }
    run run_preflight
    [ "$status" -eq 2 ]
}

@test "ARM-Architektur -> Fehler" {
    probe_arch() { printf 'arm64'; }
    run run_preflight
    [ "$status" -eq 2 ]
}

@test "Nicht root -> Fehler" {
    probe_is_root() { return 1; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"sudo"* ]]
}

@test "Kein systemd (z. B. Container) -> Fehler" {
    probe_systemd() { return 1; }
    run run_preflight
    [ "$status" -eq 2 ]
}

@test "CPU: 2 -> Fehler, 4 -> Warnung, 6 -> OK" {
    probe_cpu_count() { printf 2; }
    run run_preflight; [ "$status" -eq 2 ]
    probe_cpu_count() { printf 4; }
    run run_preflight; [ "$status" -eq 1 ]
    probe_cpu_count() { printf 6; }
    run run_preflight; [ "$status" -eq 0 ]
}

@test "RAM: 8 GB -> Fehler, 16 GB (mit Kernel-Reserve) -> Warnung, 24 GB -> OK" {
    probe_mem_kb() { printf '%d' $((8 * 1048576)); }
    run run_preflight; [ "$status" -eq 2 ]
    # 16-GB-VM meldet typischerweise ~15,6 GiB
    probe_mem_kb() { printf '%d' 16370000; }
    run run_preflight; [ "$status" -eq 1 ]
    [[ "$output" == *"Arbeitsspeicher"* ]]
    probe_mem_kb() { printf '%d' $((24 * 1048576)); }
    run run_preflight; [ "$status" -eq 0 ]
}

@test "Daten-Disk: 500 GiB und 500 GB gelten als ausreichend" {
    probe_empty_disks() { printf '/dev/sdb %d\n' 500000000000; }
    run run_preflight; [ "$status" -eq 0 ]
    [[ "$output" == *"/dev/sdb (500 GB, leer)"* ]]
}

@test "Daten-Disk: groesste geeignete Disk wird gewaehlt" {
    probe_empty_disks() { printf '/dev/sdb %d\n/dev/sdc %d\n' 600000000000 1000000000000; }
    run_preflight >/dev/null || true
    [ "$PF_DATA_DISK" = /dev/sdc ]
}

@test "Daten-Disk zu klein, Systempartition zu klein -> Fehler" {
    probe_empty_disks() { printf '/dev/sdb %d\n' 100000000000; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"zu klein"* ]]
}

@test "Keine zweite Disk, aber grosse Systempartition -> Warnung" {
    probe_empty_disks() { :; }
    probe_rootfs_kb() { printf '%d %d' 800000000 700000000; }
    run run_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"zweite Disk empfohlen"* ]]
}

@test "Keine zweite Disk, kleine Systempartition -> Fehler" {
    probe_empty_disks() { :; }
    run run_preflight
    [ "$status" -eq 2 ]
}

@test "DHCP-Adresse -> Warnung" {
    probe_ipv4() { printf 'ens192 10.0.10.50/24 dynamic\n'; }
    run run_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"DHCP"* ]]
}

@test "Keine IPv4-Adresse -> Fehler" {
    probe_ipv4() { :; }
    run run_preflight
    [ "$status" -eq 2 ]
}

@test "FQDN nicht aufloesbar -> Warnung; kein FQDN -> Warnung" {
    probe_resolve() { :; }
    run run_preflight; [ "$status" -eq 1 ]
    mock_good_system
    probe_fqdn() { printf 'siem'; }
    run run_preflight; [ "$status" -eq 1 ]
    [[ "$output" == *"kein vollqualifizierter"* ]]
}

@test "FQDN loest nur auf 127.0.1.1 auf (Debian-Standard) -> Warnung" {
    probe_resolve() { printf '127.0.1.1'; }
    run run_preflight
    [ "$status" -eq 1 ]
}

@test "Zeit nicht synchron -> Warnung" {
    probe_time_synced() { return 1; }
    run run_preflight
    [ "$status" -eq 1 ]
}

@test "Internet-Ziel nicht erreichbar -> Fehler mit Zielname" {
    probe_http() { [[ $1 != *ghcr.io* ]]; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"GitHub Container Registry"*"nicht erreichbar"* ]]
}

@test "Weder curl noch wget -> Fehler" {
    probe_http() { return 2; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"Weder curl noch wget"* ]]
}

@test "Proxy wird in der Ausgabe genannt" {
    SIEM_PROXY=http://proxy:3128
    run run_preflight
    [[ "$output" == *"über Proxy"* ]]
}

@test "Belegter Port 514/udp -> Fehler; nach SIEM-Installation nur Info" {
    probe_listening() { printf '22/tcp\n514/udp\n'; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"514/udp"* ]]
    state_set app done
    run run_preflight
    [ "$status" -eq 0 ]
    [[ "$output" == *"erwartet"* ]]
}

@test "Port 22 belegt ist erlaubt" {
    probe_listening() { printf '22/tcp\n'; }
    run run_preflight
    [ "$status" -eq 0 ]
}

@test "Fremdes Docker -> Fehler; durch SIEM installiert -> Info" {
    probe_installed_pkgs() { [[ " $* " == *" docker.io "* ]] && printf 'docker.io\n'; return 0; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"docker.io"* ]]
    state_set docker done
    run run_preflight
    [ "$status" -eq 0 ]
}

@test "Desktop-Umgebung -> Fehler" {
    probe_installed_pkgs() { [[ " $* " == *" gdm3 "* ]] && printf 'gdm3\n'; return 0; }
    run run_preflight
    [ "$status" -eq 2 ]
    [[ "$output" == *"gdm3"* ]]
}

@test "Bestehende Installation wird erkannt" {
    state_set base done
    run run_preflight
    [[ "$output" == *"--resume"* ]]
    state_set selftest done
    run run_preflight
    [[ "$output" == *"--repair"* ]]
}

@test "Ueberschriebene Schwellwerte werden gemeldet" {
    SIEM_MIN_RAM_GB=2
    run run_preflight
    [[ "$output" == *"SIEM_MIN_RAM_GB=2"* ]]
}

@test "Englische Ausgabe" {
    SIEM_LANG=en
    run run_preflight
    [[ "$output" == *"All prerequisites met"* ]]
}

@test "Preflight protokolliert, legt aber kein Zustandsverzeichnis an" {
    run run_preflight
    [ -s "$SIEM_LOG_FILE" ]
    grep -q 'PREFLIGHT' "$SIEM_LOG_FILE"
    [ ! -e "$SIEM_STATE_DIR" ]
}
