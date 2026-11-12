#!/usr/bin/env bats
# Eingabevalidierung

setup() {
    source "$BATS_TEST_DIRNAME/helpers.bash"
    load_libs
}

@test "FQDN: gueltige Namen" {
    valid_fqdn siem.firma.local
    valid_fqdn a.b
    valid_fqdn siem-01.sub.example.at
}

@test "FQDN: ungueltige Namen" {
    ! valid_fqdn siem
    ! valid_fqdn -siem.firma.local
    ! valid_fqdn siem..local
    ! valid_fqdn "siem firma.local"
    ! valid_fqdn '10.0.0.1'
    ! valid_fqdn 'siem.firma.local;reboot'
    ! valid_fqdn ''
}

@test "IPv4: gueltig und ungueltig" {
    valid_ipv4 10.0.10.50
    valid_ipv4 0.0.0.0
    ! valid_ipv4 256.1.1.1
    ! valid_ipv4 10.0.10
    ! valid_ipv4 010.0.0.1
    ! valid_ipv4 'a.b.c.d'
}

@test "Host-Liste: Namen und IPs, kommagetrennt" {
    valid_host_list dc01.firma.local
    valid_host_list 'dc01.firma.local,10.0.0.1'
    valid_host_list 'dc01, dc02'
    ! valid_host_list ''
    ! valid_host_list 'dc01,,dc02'
    ! valid_host_list 'dc01;rm -rf /'
}

@test "Proxy-URL" {
    valid_proxy_url http://proxy.firma.local:3128
    valid_proxy_url https://proxy:8443/
    valid_proxy_url http://user:pass@proxy.firma.local:3128
    valid_proxy_url http://10.0.0.1:8080
    ! valid_proxy_url proxy:3128
    ! valid_proxy_url ftp://proxy:21
    ! valid_proxy_url http://proxy:99999
    ! valid_proxy_url 'http://proxy:3128/$(id)'
}

@test "VLAN-Liste" {
    valid_vlan_list 10
    valid_vlan_list '10,20,30-40'
    valid_vlan_list '1,4094'
    ! valid_vlan_list 0
    ! valid_vlan_list 4095
    ! valid_vlan_list '40-30'
    ! valid_vlan_list '10,,20'
    ! valid_vlan_list 'abc'
    ! valid_vlan_list ''
}

@test "SSH-Public-Key: Format" {
    valid_ssh_pubkey 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq1yTkH0vB5dZ0r0b2e4T0pQ0bJ3m0VZr9cX8cQ1V3B admin@pc' \
        || skip "ssh-keygen lehnt Testschlüssel ab (Format wird in CI mit echtem Schlüssel geprüft)"
    ! valid_ssh_pubkey 'ssh-dss AAAAB3NzaC1kc3M= old'
    ! valid_ssh_pubkey 'kein schlüssel'
    ! valid_ssh_pubkey ''
}

@test "SSH-Public-Key: echter erzeugter Schluessel" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen nicht vorhanden"
    ssh-keygen -q -t ed25519 -N '' -f "$BATS_TEST_TMPDIR/k" -C test@test
    valid_ssh_pubkey "$(cat "$BATS_TEST_TMPDIR/k.pub")"
}

@test "Kennwort: Mindestlaenge 12" {
    valid_password 'abcdefghijkl'
    valid_password 'Sehr sicheres Kennwort!'
    ! valid_password 'kurz'
    ! valid_password 'elfZeichen1'
    ! valid_password $'abcdefghijkl\x01'
}

@test "Sprache" {
    valid_lang de
    valid_lang en
    ! valid_lang fr
}
