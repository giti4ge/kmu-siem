# shellcheck shell=bash
# Schritt "datadisk": Daten-Disk mit LVM einrichten und unter /opt/siem/data einhängen.
#
# Idempotent: Ist die Volume Group "siem" mit LV "data" bereits vorhanden, wird nur
# Einhängepunkt/fstab sichergestellt. Eine Disk wird ausschließlich gelöscht, wenn
# sie unmittelbar vorher als leer erkannt wurde UND die Löschung bestätigt ist.

readonly SIEM_VG=siem
readonly SIEM_LV=data
readonly DATA_MOUNT_OPTS="defaults,nodev,nosuid,noexec"

step_datadisk() {
    local disk=${ANSWERS[SIEM_DATA_DISK]:-none} dev
    install -d -m 0755 "$SIEM_ROOT" || return 1

    if [[ $disk == none ]]; then
        install -d -m 0750 "$SIEM_ROOT/data" || return 1
        _datadisk_layout
        return
    fi

    dev="/dev/$SIEM_VG/$SIEM_LV"
    if ! lvs "$SIEM_VG/$SIEM_LV" >/dev/null 2>&1; then
        _datadisk_create "$disk" || return 1
    else
        log INFO "LV $SIEM_VG/$SIEM_LV vorhanden – keine Neuanlage"
    fi
    _datadisk_mount "$dev" || return 1
    _datadisk_layout
}

_datadisk_create() {
    local disk=$1 name
    [[ ${ANSWERS[SIEM_DATA_DISK_CONFIRM]:-} == yes ]] || { err "Löschung von $disk nicht bestätigt"; return 1; }
    # Sicherheitsprüfung unmittelbar vor dem Löschen
    local empty=0
    while read -r name _; do [[ $name == "$disk" ]] && empty=1; done < <(probe_empty_disks)
    (( empty )) || { err "$disk ist nicht (mehr) leer – Abbruch ohne Änderung"; return 1; }

    run_cmd "Physical Volume $disk" pvcreate -y "$disk" || return 1
    run_cmd "Volume Group $SIEM_VG" vgcreate "$SIEM_VG" "$disk" || return 1
    run_cmd "Logical Volume $SIEM_LV" lvcreate -y -l 100%FREE -n "$SIEM_LV" "$SIEM_VG" || return 1
    run_cmd "Dateisystem anlegen" mkfs.ext4 -q -L siem-data -m 1 "/dev/$SIEM_VG/$SIEM_LV" || return 1
}

_datadisk_mount() {
    local dev=$1 uuid mnt="$SIEM_ROOT/data" tmp
    uuid=$(blkid -s UUID -o value "$dev") || { err "UUID von $dev nicht lesbar"; return 1; }
    install -d -m 0750 "$mnt" || return 1
    # fstab: genau ein Eintrag für den Einhängepunkt
    tmp=$(mktemp) || return 1
    awk -v m="$mnt" '$2 != m' /etc/fstab >"$tmp"
    printf 'UUID=%s %s ext4 %s 0 2\n' "$uuid" "$mnt" "$DATA_MOUNT_OPTS" >>"$tmp"
    if ! cmp -s "$tmp" /etc/fstab; then
        cp -a /etc/fstab "/etc/fstab.siem-backup" 2>/dev/null || true
        cat "$tmp" >/etc/fstab
        run_cmd "systemd neu laden" systemctl daemon-reload || true
    fi
    rm -f "$tmp"
    if ! findmnt -n "$mnt" >/dev/null; then
        run_cmd "Daten-Disk einhängen" mount "$mnt" || return 1
    fi
    chmod 0750 "$mnt"
}

# Verzeichnisstruktur auf der Daten-Disk
_datadisk_layout() {
    local d
    for d in config-db opensearch opensearch-snapshots vector-buffer openwec archive reports content backups; do
        install -d -m 0750 "$SIEM_ROOT/data/$d"
    done
    install -d -m 0700 "$SIEM_ROOT/data/secrets"
    # /opt/siem/backups liegt auf der Daten-Disk
    if [[ ! -L $SIEM_ROOT/backups ]]; then
        rmdir "$SIEM_ROOT/backups" 2>/dev/null || true
        ln -sfn data/backups "$SIEM_ROOT/backups"
    fi
    return 0
}
