"""KI-Bridge: Anbieter-Anfragen, Pseudonymisierung/Rückübersetzung, Beweisbindung, Zweitlauf, Limits."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siem_api import ai

CFG = {"enabled": True, "provider": "anthropic", "model": "", "base_url": "", "anonymize": True,
       "daily_token_limit": 200000}
EVENTS = [
    {"@timestamp": "2026-11-14T08:00:00Z", "event": {"dataset": "windows.security", "action": "logon-failed", "outcome": "failure"},
     "host": {"name": "srv-dc01"}, "user": {"name": "mueller"}, "source": {"ip": "203.0.113.9"}, "message": "failed"},
    {"@timestamp": "2026-11-14T08:05:00Z", "event": {"dataset": "windows.security", "action": "logon", "outcome": "success"},
     "host": {"name": "srv-dc01"}, "user": {"name": "mueller"}, "source": {"ip": "203.0.113.9"}, "message": "ok"},
]


def mk(tmp_path: Path, **over) -> ai.Store:
    s = ai.Store(tmp_path, b"k" * 32)
    s.save({**CFG, **over}, "geheimer-api-schluessel")
    return s


def reply(text: str, tokens: int = 100):
    def transport(url, headers, body):
        transport.calls.append((url, headers, body))
        return {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": tokens, "output_tokens": 0}}
    transport.calls = []
    return transport


def test_key_encrypted(tmp_path):
    s = mk(tmp_path)
    assert "geheimer" not in (tmp_path / "ai.json").read_text("utf-8")
    assert s.api_key() == "geheimer-api-schluessel" and s.config()["has_key"]
    assert "geheimer" not in json.dumps(s.config())


def test_external_providers_always_anonymize(tmp_path):
    assert mk(tmp_path, provider="gemini", anonymize=False).config()["anonymize"] is True
    assert mk(tmp_path, provider="custom", base_url="http://llm.lan:11434/v1", anonymize=False).config()["anonymize"] is False


@pytest.mark.parametrize("provider,url_part,header", [
    ("anthropic", "api.anthropic.com/v1/messages", "x-api-key"),
    ("gemini", "generativelanguage.googleapis.com", "x-goog-api-key"),
    ("openai", "api.openai.com/v1/chat/completions", "Authorization"),
])
def test_build_request(tmp_path, provider, url_part, header):
    s = mk(tmp_path, provider=provider)
    url, headers, body = ai.build_request(s.config(), "K", "sys", "usr")
    assert url_part in url and header in headers and "usr" in json.dumps(body)


def test_azure_and_custom_urls(tmp_path):
    s = mk(tmp_path, provider="azure", model="gpt4", base_url="https://res.openai.azure.com")
    url, headers, _ = ai.build_request(s.config(), "K", "s", "u")
    assert url.startswith("https://res.openai.azure.com/openai/deployments/gpt4/chat/completions") and "api-key" in headers
    c = mk(tmp_path, provider="custom", base_url="http://10.0.0.5:11434/v1", model="llama")
    assert ai.build_request(c.config(), "", "s", "u")[0] == "http://10.0.0.5:11434/v1/chat/completions"


def test_parse_responses():
    assert ai.parse_response("openai", {"choices": [{"message": {"content": "hi"}}], "usage": {"total_tokens": 7}}) == ("hi", 7)
    assert ai.parse_response("gemini", {"candidates": [{"content": {"parts": [{"text": "a"}, {"text": "b"}]}}],
                                        "usageMetadata": {"totalTokenCount": 5}}) == ("ab", 5)
    with pytest.raises(ai.AiError):
        ai.parse_response("anthropic", {"x": 1})


def test_explain_pseudonymizes_and_restores(tmp_path):
    s = mk(tmp_path)
    p = ai.make_pseudonymizer(tmp_path, True, ["srv-dc01"], ["mueller"])
    alert = {"rule": "Brute force", "severity": "high", "group": "203.0.113.9", "count": 30,
             "summary": "30 Fehlversuche von 203.0.113.9 für mueller", "sample": "host srv-dc01", "mitre": ["T1110"]}
    t = reply("Die Quelle IP4_PLACEHOLDER")
    test = ai.explain_alert(s, p, alert, test=True)
    assert "203.0.113.9" not in test["request"]["user"] and "mueller" not in test["request"]["user"]
    ph = p.line("203.0.113.9")
    t = reply(f"Sperren Sie {ph}.")
    out = ai.explain_alert(s, p, alert, transport=t)
    assert "203.0.113.9" in out["text"] and "zu prüfen" in out["disclaimer"]
    sent = json.dumps(t.calls[0][2])
    assert "203.0.113.9" not in sent and "mueller" not in sent and "srv-dc01" not in sent


def test_verify_drops_unevidenced_and_invalid_ids():
    res = {"timeline": [{"time": "t", "statement": "ok", "evidence": ["E1"]},
                        {"time": "t", "statement": "erfunden", "evidence": ["E99"]},
                        {"time": "t", "statement": "ohne", "evidence": []}, "kaputt"],
           "initial_access": {"statement": "x", "evidence": ["E2", "E50"]},
           "scope": [{"statement": "s", "evidence": ["E2"]}], "gaps": ["Lücke"]}
    v = ai.verify(res, {"E1", "E2"})
    assert [x["statement"] for x in v["timeline"]] == ["ok"] and v["rejected"] == 3
    assert v["initial_access"]["evidence"] == ["E2"] and v["scope"][0]["verified"] and v["gaps"] == ["Lücke"]
    assert ai.verify({"initial_access": {"statement": "x", "evidence": ["E9"]}}, {"E1"})["initial_access"] is None


def test_analyze_two_runs_and_contradiction(tmp_path):
    s = mk(tmp_path)
    p = ai.make_pseudonymizer(tmp_path, True, ["srv-dc01"], ["mueller"])
    good = json.dumps({"timeline": [{"time": "08:00", "statement": "Fehlversuch", "evidence": ["E1"]}],
                       "initial_access": {"statement": "Anmeldung", "evidence": ["E2"]}, "scope": [], "gaps": []})
    other = json.dumps({"timeline": [], "initial_access": {"statement": "anders", "evidence": ["E1"]}, "scope": [], "gaps": []})
    answers = iter([good, other])
    calls = []

    def transport(url, headers, body):
        calls.append(body)
        return {"content": [{"type": "text", "text": next(answers)}], "usage": {"input_tokens": 10, "output_tokens": 5}}

    out = ai.analyze(s, p, EVENTS, transport=transport)
    assert len(calls) == 2 and out["events"] == 2 and out["initial_access"]["evidence"] == ["E2"]
    assert out["contradictions"] and "Kein Beweismittel" in out["disclaimer"]
    user = calls[0]["messages"][0]["content"]
    assert "[E1]" in user and "mueller" not in user and "203.0.113.9" not in user and "srv-dc01" not in user


def test_analyze_test_mode_and_empty(tmp_path):
    s = mk(tmp_path, enabled=False)
    p = ai.make_pseudonymizer(tmp_path, True, [], [])
    assert "[E1]" in ai.analyze(s, p, EVENTS, test=True)["request"]["user"]  # Testmodus braucht keine Aktivierung
    assert ai.analyze(s, p, [])["gaps"]


def test_disabled_and_limit(tmp_path):
    s = mk(tmp_path, enabled=False)
    with pytest.raises(ai.AiError) as e:
        ai.complete(s, "s", "u", reply("x"))
    assert e.value.code == "ai_disabled"
    s2 = mk(tmp_path, daily_token_limit=1000)
    ai.complete(s2, "s", "u", reply("x", tokens=1500))
    with pytest.raises(ai.AiError) as e2:
        ai.complete(s2, "s", "u", reply("x"))
    assert e2.value.code == "ai_limit_reached"


def test_api_requires_login(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/ai").status_code in (401, 403)
    assert c.post("/api/ai/forensics", json={"field": "user.name", "value": "x"}).status_code in (401, 403)
