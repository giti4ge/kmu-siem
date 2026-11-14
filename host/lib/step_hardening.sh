# shellcheck shell=bash
# Schritt "hardening": CIS-orientierte Härtung des Hosts.
#   sysctl, Kernel-Module, Admin-Benutzer siemadmin, SSH, auditd, chrony,
#   unattended-upgrades, AppArmor-Prüfung.
# AIDE wird erst im Selbsttest initialisiert (nach allen Dateiänderungen).

readonly SIEM_ADMIN_USER=siemadmin
readonly SIEM_SSH_GROUP=siem-ssh
readonly SSHD_DROPIN=/etc/ssh/sshd_config.d/00-siem.conf

step_hardening() {
    _hard_sysctl || return 1
    _hard_extras || return 1
    _hard_modules || return 1
    _hard_admin_user || return 1
    _hard_ssh || return 1
    _hard_auditd || return 1
    _hard_time || return 1
    _hard_updates || return 1
    _hard_apparmor || return 1
}

# --- Kernel-Parameter --------------------------------------------------------
_hard_sysctl() {
    local rc
    write_file /etc/sysctl.d/99-siem-hardening.conf 0644 <<'EOF'
# Von install.sh verwaltet – KMU-SIEM Härtung
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.ctrl-alt-del = 0
dev.tty.ldisc_autoload = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
# OpenSearch
vm.max_map_count = 262144
vm.swappiness = 1
# Weiterleitung nur für ausgehenden Verkehr der Container-Bridge (Docker);
# die nftables-Forward-Kette lässt ausschließlich diesen Verkehr zu.
net.ipv4.ip_forward = 1
EOF
    rc=$?; (( rc <= 1 )) || return 1
    run_cmd "Kernel-Parameter laden" sysctl --system
}

# --- Ergänzende Härtung (CIS/Lynis) ---------------------------------------------
readonly SIEM_BANNER="Autorisierter Zugriff nur für berechtigte Administratoren. Alle Aktivitäten werden protokolliert.
Authorized access only. All activities are logged."

_hard_extras() {
    local rc f
    # Core-Dumps verhindern (können Geheimnisse enthalten)
    write_file /etc/security/limits.d/90-siem.conf 0644 <<'EOF'
# Von install.sh verwaltet
*    hard    core    0
EOF
    rc=$?; (( rc <= 1 )) || return 1
    write_file /etc/systemd/coredump.conf.d/90-siem.conf 0644 <<'EOF'
# Von install.sh verwaltet
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    rc=$?; (( rc <= 1 )) || return 1

    # Anmelde-Banner (lokal und SSH)
    printf '%s\n' "$SIEM_BANNER" | write_file /etc/issue 0644; (( $? <= 1 )) || return 1
    printf '%s\n' "$SIEM_BANNER" | write_file /etc/issue.net 0644; (( $? <= 1 )) || return 1

    # Vorgaben für neue Konten: restriktive umask, Kennwort-Alterung
    # (siemadmin selbst ohne Ablauf – ein abgelaufenes Kennwort würde den Wartungszugang blockieren)
    _login_defs UMASK 027
    _login_defs PASS_MAX_DAYS 365
    _login_defs PASS_MIN_DAYS 1
    _login_defs PASS_WARN_AGE 14

    # Rechte von cron und SSH-Konfiguration
    for f in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -e $f ]] && chmod og-rwx "$f"
    done
    chmod 0600 /etc/ssh/sshd_config

    # Prozess-Accounting und Systemstatistik
    systemctl enable --now acct.service >/dev/null 2>&1 || true
    if [[ -f /etc/default/sysstat ]] && ! grep -q '^ENABLED="true"' /etc/default/sysstat; then
        sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
    fi
    systemctl enable --now sysstat.service >/dev/null 2>&1 || true

    # rkhunter: Dateieigenschaften nach Paket-Updates automatisch aktualisieren
    if [[ -f /etc/default/rkhunter ]]; then
        sed -i -E 's/^#?APT_AUTOGEN=.*/APT_AUTOGEN="true"/; s/^#?CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
    fi
    return 0
}

# _login_defs SCHLÜSSEL WERT – Wert in /etc/login.defs setzen (idempotent)
_login_defs() {
    if grep -qE "^[[:space:]]*$1[[:space:]]" /etc/login.defs; then
        sed -i -E "s/^[[:space:]]*$1[[:space:]].*/$1\t\t$2/" /etc/login.defs
    else
        printf '%s\t\t%s\n' "$1" "$2" >>/etc/login.defs
    fi
}

# --- Kernel-Module -----------------------------------------------------------
_hard_modules() {
    local m content="# Von install.sh verwaltet – nicht benötigte Module"$'\n' rc
    for m in usb-storage uas bluetooth btusb firewire-core firewire-ohci firewire-sbp2 \
             cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do
        content+="blacklist $m"$'\n'"install $m /bin/false"$'\n'
    done
    printf '%s' "$content" | write_file /etc/modprobe.d/siem-blacklist.conf 0644
    rc=$?; (( rc <= 1 ))
}

# --- Admin-Benutzer ------------------------------------------------------------
_hard_admin_user() {
    local secret="$SIEM_STATE_DIR/secrets/admin_password" key=${ANSWERS[SIEM_ADMIN_SSH_KEY]:-}
    getent group "$SIEM_SSH_GROUP" >/dev/null || run_cmd "Gruppe $SIEM_SSH_GROUP" groupadd --system "$SIEM_SSH_GROUP" || return 1
    if ! id "$SIEM_ADMIN_USER" >/dev/null 2>&1; then
        run_cmd "Benutzer $SIEM_ADMIN_USER anlegen" \
            useradd -m -s /bin/bash -G "sudo,$SIEM_SSH_GROUP,adm" -c "KMU-SIEM Administrator" "$SIEM_ADMIN_USER" || return 1
    else
        usermod -aG "sudo,$SIEM_SSH_GROUP,adm" "$SIEM_ADMIN_USER" || return 1
    fi
    if [[ -f $secret ]]; then
        printf '%s:%s\n' "$SIEM_ADMIN_USER" "$(cat "$secret")" | chpasswd || { err "Kennwort für $SIEM_ADMIN_USER nicht gesetzt"; return 1; }
        shred -u "$secret" 2>/dev/null || rm -f "$secret"
        log INFO "Kennwort für $SIEM_ADMIN_USER gesetzt"
    fi
    if [[ -n $key ]]; then
        local home
        home=$(getent passwd "$SIEM_ADMIN_USER" | cut -d: -f6)
        install -d -m 0700 -o "$SIEM_ADMIN_USER" -g "$SIEM_ADMIN_USER" "$home/.ssh" || return 1
        if ! grep -qxF "$key" "$home/.ssh/authorized_keys" 2>/dev/null; then
            printf '%s\n' "$key" >>"$home/.ssh/authorized_keys"
        fi
        chown "$SIEM_ADMIN_USER:$SIEM_ADMIN_USER" "$home/.ssh/authorized_keys"
        chmod 0600 "$home/.ssh/authorized_keys"
    fi
    # Installationsbenutzer behält SSH-Zugang nur auf Wunsch
    if [[ ${ANSWERS[SIEM_KEEP_INSTALLER_USER_SSH]:-} == yes && -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        usermod -aG "$SIEM_SSH_GROUP" "$SUDO_USER" || return 1
    fi
    return 0
}

# --- SSH ------------------------------------------------------------------------
# Kennwort-Anmeldung wird nur abgeschaltet, wenn ein Schlüssel hinterlegt ist UND
# die Anmeldung damit bestätigt wurde (interaktiv) bzw. ausdrücklich gewünscht ist
# (Antwortdatei: SIEM_SSH_PASSWORD_AUTH=no).
_hard_ssh() {
    _ssh_write_config yes || return 1
    [[ -n ${ANSWERS[SIEM_ADMIN_SSH_KEY]:-} ]] || { warn "$(msg q_sshkey_none)"; return 0; }

    local disable=no
    if [[ ${ANSWERS[SIEM_SSH_PASSWORD_AUTH]:-} == no ]]; then
        disable=yes
    elif [[ ${ANSWERS[SIEM_SSH_PASSWORD_AUTH]:-} == yes ]]; then
        disable=no
    elif [[ ${MODE:-} != unattended && -t 0 ]]; then
        info "$(msg ssh_test_hint "$SIEM_ADMIN_USER" "$(probe_fqdn)")"
        confirm "$(msg ssh_test_confirm "$SIEM_ADMIN_USER")" && disable=yes
    fi
    if [[ $disable == yes ]]; then
        _ssh_write_config no || return 1
        ANSWERS[SIEM_SSH_PASSWORD_AUTH]=no
        ok "$(msg ssh_pw_disabled)"
    else
        ANSWERS[SIEM_SSH_PASSWORD_AUTH]=yes
        warn "$(msg ssh_pw_kept)"
    fi
    save_answers
}

# _ssh_write_config PASSWORT_AUTH(yes|no)
_ssh_write_config() {
    local pw=$1 rc
    write_file "$SSHD_DROPIN" 0644 <<EOF
# Von install.sh verwaltet – KMU-SIEM SSH-Härtung
# Dateiname 00-… : sshd übernimmt jeweils den ERSTEN gefundenen Wert.
PermitRootLogin no
PasswordAuthentication ${pw}
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AllowGroups ${SIEM_SSH_GROUP}
MaxAuthTries 3
MaxSessions 2
Compression no
TCPKeepAlive no
Banner /etc/issue.net
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
LogLevel VERBOSE
KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Support-Zugang: Schlüssel setzt nur siem-hostd (zeitlich begrenzt), nur Allowlist-Befehle, kein Terminal
Match User siem-support
    AuthorizedKeysFile ${SIEM_ROOT}/data/hostd/support/authorized_keys
    ForceCommand /usr/local/sbin/siem-support-shell
    PermitTTY no
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication no
EOF
    rc=$?
    (( rc <= 1 )) || return 1
    if ! sshd -t 2>>"$SIEM_LOG_FILE"; then
        err "$(msg ssh_config_invalid)"
        rm -f "$SSHD_DROPIN"
        return 1
    fi
    if (( rc == 0 )); then
        run_cmd "SSH neu laden" systemctl reload ssh.service || return 1
    fi
    return 0
}

# --- auditd ---------------------------------------------------------------------
_hard_auditd() {
    local rc
    # Überwachte Verzeichnisse müssen existieren, sonst schlägt das Laden fehl
    install -d -m 0755 /etc/docker "$SIEM_ROOT/host" || return 1
    write_file /etc/audit/rules.d/50-siem.rules 0640 <<'EOF'
## Von install.sh verwaltet – KMU-SIEM Audit-Regeln
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/nftables.conf -p wa -k firewall
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/modprobe.d/ -p wa -k modules
-w /etc/docker/ -p wa -k docker
-w /opt/siem/host/ -p wa -k siem-host
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-commands
EOF
    rc=$?; (( rc <= 1 )) || return 1
    svc_enable_now auditd || return 1
    if (( rc == 0 )); then
        run_cmd "Audit-Regeln laden" augenrules --load || return 1
    fi
    return 0
}

# --- Zeit (chrony) -------------------------------------------------------------------
_hard_time() {
    local servers=${ANSWERS[SIEM_NTP]:-} s content rc rc2
    content="# Von install.sh verwaltet – NTP-Server der Appliance"$'\n'
    IFS=, read -r -a list <<<"$servers"
    for s in "${list[@]}"; do
        s=$(trim "$s"); [[ -n $s ]] && content+="server $s iburst"$'\n'
    done
    printf '%s' "$content" | write_file /etc/chrony/sources.d/siem.sources 0644
    rc=$?; (( rc <= 1 )) || return 1
    # Standard-Pool deaktivieren, damit nur die konfigurierten Server gelten
    if grep -qE '^(pool|server) ' /etc/chrony/chrony.conf; then
        sed -i -E 's/^((pool|server) .*)$/# \1  # deaktiviert durch install.sh/' /etc/chrony/chrony.conf
        rc2=0
    else
        rc2=1
    fi
    svc_enable_now chrony || return 1
    if (( rc == 0 || rc2 == 0 )); then
        run_cmd "chrony neu starten" systemctl restart chrony || return 1
    fi
    return 0
}

# --- Automatische Sicherheitsupdates ----------------------------------------------
_hard_updates() {
    local rc1 rc2
    write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
// Von install.sh verwaltet
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    rc1=$?
    write_file /etc/apt/apt.conf.d/52siem-unattended-upgrades 0644 <<'EOF'
// Von install.sh verwaltet – Reboot-Fenster wird später über das Web-UI gesetzt
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
Unattended-Upgrade::SyslogEnable "true";
EOF
    rc2=$?
    (( rc1 <= 1 && rc2 <= 1 ))
}

# --- AppArmor ------------------------------------------------------------------------
_hard_apparmor() {
    if ! aa-enabled --quiet 2>/dev/null; then
        warn "$(msg apparmor_disabled)"
    fi
    return 0
}
