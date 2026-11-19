"""Explainer tests: no-key path, mocked success, mocked failure.

No real Gemini call is made. The mocked transport stands in for
_call_gemini; the assertions pin the contract that matters — the
explanation is garnish on a finished verdict and can never move the
score.
"""

import pathlib

import pytest
from fastapi.testclient import TestClient

from app.api.analyze import _result
from app.main import app
from app.services import explainer

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
PAYPAL = (SAMPLES / "phishing_paypal.eml").read_bytes().decode("utf-8", errors="replace")

client = TestClient(app)


@pytest.fixture(autouse=True)
def _no_key_by_default(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)


def test_no_key_returns_clean_unavailable():
    response = client.post("/explain/email", json={"raw": PAYPAL})
    assert response.status_code == 200
    body = response.json()
    assert body == {"available": False, "reason": "GEMINI_API_KEY not configured"}


def test_mocked_success_explains_without_touching_score(monkeypatch):
    captured = {}

    def fake_call(prompt, api_key, model, timeout=explainer.TIMEOUT_SECONDS):
        captured["prompt"] = prompt
        captured["model"] = model
        return "This email pretends to be from PayPal but its authentication failed and its link leads to a bare IP address. Do not use the link; sign in only through the official app."

    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setattr(explainer, "_call_gemini", fake_call)

    expected = _result(PAYPAL)
    response = client.post("/explain/email", json={"raw": PAYPAL})
    body = response.json()
    assert body["available"] is True
    assert body["model"] == "gemini-3.5-flash"
    assert body["score_unchanged"] == expected["verdict"]["score"]
    assert body["verdict_unchanged"] == expected["verdict"]["verdict"]
    # The prompt was built from the structured reasons, not the raw mail.
    top_reason = expected["verdict"]["reasons"][0]["detail"]
    assert top_reason in captured["prompt"]
    assert "Dear customer" not in captured["prompt"]


def test_mocked_failure_is_fail_open(monkeypatch):
    def boom(prompt, api_key, model, timeout=explainer.TIMEOUT_SECONDS):
        raise TimeoutError("slow")

    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setattr(explainer, "_call_gemini", boom)
    response = client.post("/explain/email", json={"raw": PAYPAL})
    body = response.json()
    assert body["available"] is False
    assert "Gemini request failed" in body["reason"]
