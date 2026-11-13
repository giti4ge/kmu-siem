# Gemeinsame Test-Hilfen für die Installer-Tests (bats)

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
HOST_DIR="$REPO_ROOT/host"

load_libs() {
    export NO_COLOR=1
    export SIEM_LANG=de
    export SIEM_LOG_FILE="$BATS_TEST_TMPDIR/install.log"
    export SIEM_STATE_DIR="$BATS_TEST_TMPDIR/state"
    # shellcheck source=/dev/null
    . "$HOST_DIR/lib/common.sh"
    . "$HOST_DIR/lib/i18n.sh"
    . "$HOST_DIR/lib/validate.sh"
    . "$HOST_DIR/lib/state.sh"
    . "$HOST_DIR/lib/answers.sh"
    . "$HOST_DIR/lib/preflight.sh"
    . "$HOST_DIR/lib/prompts.sh"
    . "$HOST_DIR/lib/steps.sh"
}

# Simuliert ein System, das alle Voraussetzungen erfüllt.
# Einzelne Tests überschreiben danach gezielt einzelne probe_*-Funktionen.
mock_good_system() {
    probe_os()              { printf 'debian|13|Debian GNU/Linux 13 (trixie)'; }
    probe_arch()            { printf 'amd64'; }
    probe_is_root()         { return 0; }
    probe_systemd()         { return 0; }
    probe_cpu_count()       { printf '8'; }
    probe_mem_kb()          { printf '%d' $((24 * 1048576)); }
    probe_rootfs_kb()       { printf '%d %d' $((40 * 1000000)) $((35 * 1000000)); }
    probe_empty_disks()     { printf '/dev/sdb %d\n' $((500 * 1073741824)); }
    probe_ipv4()            { printf 'ens192 10.0.10.50/24 static\n'; }
    probe_fqdn()            { printf 'siem.firma.local'; }
    probe_resolve()         { printf '10.0.10.50'; }
    probe_time_synced()     { return 0; }
    probe_http()            { return 0; }
    probe_listening()       { printf '22/tcp\n'; }
    probe_installed_pkgs()  { return 0; }
}
