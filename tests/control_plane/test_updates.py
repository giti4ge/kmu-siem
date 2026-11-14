"""Update-Prüfung: Versionsvergleich, Kanäle, verschlüsseltes Token, Fehlerfälle."""

from __future__ import annotations

import pytest

from siem_api import updates as up

REL = [
    {"tag_name": "v0.2.0-beta.1", "prerelease": True, "name": "b", "body": "beta"},
    {"tag_name": "v0.1.5", "prerelease": False, "name": "s", "body": "stable", "html_url": "u"},
    {"tag_name": "v9.9.9", "draft": True},
    {"tag_name": "kaputt"},
]


def test_parse_ordering():
    assert up.parse("1.2.3") > up.parse("1.2.3-beta.1") > up.parse("1.2.2")
    assert up.parse("v0.1.0-dev") < up.parse("0.1.0")
    assert up.parse("x") is None


def test_newest_channels():
    s = up.newest(REL, "stable", "0.1.0-dev")
    assert s and s["version"] == "0.1.5" and not s["prerelease"]
    assert up.newest(REL, "beta", "0.1.0-dev")["version"] == "0.2.0-beta.1"
    assert up.newest(REL, "stable", "0.1.5") is None  # nichts Neueres
    assert up.newest([], "stable", "0.1.0") is None


def test_store_token_encrypted_and_validation(tmp_path):
    s = up.Store(tmp_path, b"k" * 32)
    s.save("giti4ge/kmu-siem-releases", "beta", "ghp_geheim")
    assert "ghp_geheim" not in (tmp_path / "updates.json").read_text("utf-8")
    assert s.token() == "ghp_geheim" and s.config()["has_token"] and s.config()["channel"] == "beta"
    for repo, ch in (("kein repo", "stable"), ("a/b", "nightly"), ("../x/y", "stable")):
        with pytest.raises(up.UpdateError):
            s.save(repo, ch, None)


def test_check_uses_repo_and_remembers(tmp_path):
    s = up.Store(tmp_path, b"k" * 32)
    urls = []

    def fake(url, token):
        urls.append((url, token))
        return REL

    out = up.check(s, fake)
    assert "repos/giti4ge/kmu-siem-releases/releases" in urls[0][0] and out["latest"]["version"] == "0.1.5"
    assert s.config()["latest"]["version"] == "0.1.5" and s.config()["last_check"]


def test_api_requires_login(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/updates").status_code in (401, 403)
    assert c.post("/api/updates/check").status_code in (401, 403)
