"""Linux-Onboarding: Eingabeprüfung, Skriptinhalt, API-Rechte."""

from __future__ import annotations

import subprocess

import pytest

from siem_api import linux_onboarding as lo

CA = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUabc=\n-----END CERTIFICATE-----\n"


def test_server_validation_blocks_injection():
    assert lo.validate_server("siem.firma.local") == "siem.firma.local"
    assert lo.validate_server("10.0.0.5") == "10.0.0.5"
    for bad in ("", "a b", "x;rm -rf /", "$(id)", "a'b", "a\nb", "-x", "x" * 300):
        with pytest.raises(lo.LinuxOnboardingError):
            lo.validate_server(bad)


def test_ca_must_be_plain_pem(tmp_path):
    (tmp_path / "opensearch-ca.crt").write_text(CA)
    assert lo.read_ca(tmp_path) == CA
    (tmp_path / "opensearch-ca.crt").write_text(CA + "SIEM_CA_EOF\nrm -rf /\n")
    with pytest.raises(lo.LinuxOnboardingError):
        lo.read_ca(tmp_path)
    with pytest.raises(lo.LinuxOnboardingError):
        lo.read_ca(tmp_path / "fehlt")


def test_script_content_and_shell_syntax(tmp_path):
    for audit in (False, True):
        script = lo.render_script("siem.firma.local", CA, audit)
        assert "@@" not in script
        assert "SERVER='siem.firma.local'" in script and "PORT=6514" in script
        assert f"WITH_AUDIT={int(audit)}" in script
        assert "-----BEGIN CERTIFICATE-----" in script and "StreamDriverMode=\"1\"" in script
        assert "-w /etc/sudoers" in script
        p = tmp_path / "s.sh"
        p.write_bytes(script.encode())
        r = subprocess.run(["sh", "-n", str(p)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_api_requires_write_permission(h, settings):
    (settings.secrets_dir / "opensearch-ca.crt").write_text(CA)
    h.create_user("adm", ["system-admin"])
    h.create_user("leser", ["auditor"])
    c = h.login("adm")
    r = c.get("/api/linux/script", params={"server": "siem.firma.local", "audit": "true"})
    assert r.status_code == 200 and len(r.headers["X-Script-SHA256"]) == 64 and "WITH_AUDIT=1" in r.text
    assert c.get("/api/linux/script", params={"server": "x;y"}).json()["detail"]["error"] == "linux_invalid_server"
    assert h.login("leser").get("/api/linux/script", params={"server": "siem.firma.local"}).status_code == 403
