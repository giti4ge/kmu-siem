"""MITRE ATT&CK: Katalog deckt alle Regeln ab, Abdeckungsmatrix und Rechte."""

from __future__ import annotations

from dataclasses import replace

from siem_api import alerts as al
from siem_api import mitre


def test_all_rule_techniques_are_in_catalog():
    for r in al.BUILTIN_RULES:
        for t in r.mitre:
            assert t in mitre.TECHNIQUES, (r.id, t)


def test_info_has_name_tactics_and_link():
    i = mitre.info(("T1070.001",))[0]
    assert i["name"].endswith("Clear Windows Event Logs") and i["tactics"] == ["defense-evasion"]
    assert i["url"] == "https://attack.mitre.org/techniques/T1070/001/"


def test_matrix_status_covered_disabled_gap():
    rules = [r if r.id != "win-log-cleared" else replace(r, enabled=False) for r in al.BUILTIN_RULES]
    m = mitre.matrix(rules)
    st = {t["id"]: t["status"] for c in m["tactics"] for t in c["techniques"]}
    assert st["T1110"] == "covered" and st["T1070.001"] == "disabled" and st["T1486"] == "gap"
    s = m["summary"]
    assert s["covered"] + s["disabled"] + s["gaps"] == s["techniques"]
    assert [c["tactic"] for c in m["tactics"]] == list(mitre.TACTICS)
