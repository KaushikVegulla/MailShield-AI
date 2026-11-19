"""Second-opinion tests — run without torch installed.

Pins the three properties that matter: disabled by default, the
stubbed-pipeline path returns a sane advisory block, and the hybrid
verdict is identical whether the second opinion is on or off.
"""

import pathlib

import pytest

from app.api.analyze import _result
from app.core.parser import parse_email
from app.ml import second_opinion as so

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("SECOND_OPINION_MODEL", raising=False)
    so._cache = None
    so._load_error = None
    yield
    so._cache = None
    so._load_error = None


def test_disabled_by_default_block_shape():
    parsed = parse_email((SAMPLES / "phishing_paypal.eml").read_bytes())
    block = so.second_opinion(parsed)
    assert block["available"] is False
    assert "SECOND_OPINION_MODEL" in block["reason"]


def test_stubbed_pipeline_scoring_path(monkeypatch):
    def fake_classifier(model_name):
        def classify(text):
            return {"legitimate_email": 0.05, "phishing_url": 0.80, "legitimate_url": 0.03, "phishing_url_alt": 0.12}

        return classify

    monkeypatch.setenv("SECOND_OPINION_MODEL", "stub/model")
    monkeypatch.setattr(so, "_get_classifier", fake_classifier)
    parsed = parse_email((SAMPLES / "phishing_paypal.eml").read_bytes())
    block = so.second_opinion(parsed)
    assert block["available"] is True
    assert block["top_label"] == "phishing_url"
    assert block["phishing_probability"] == pytest.approx(0.92)
    assert block["class_probabilities"]["legitimate_email"] == 0.05


def test_verdict_identical_with_second_opinion_on_or_off(monkeypatch):
    raw = (SAMPLES / "phishing_paypal.eml").read_bytes()
    off = _result(raw)

    def fake_classifier(model_name):
        return lambda text: {"legitimate_email": 0.97, "phishing_url": 0.01, "legitimate_url": 0.01, "phishing_url_alt": 0.01}

    monkeypatch.setenv("SECOND_OPINION_MODEL", "stub/model")
    monkeypatch.setattr(so, "_get_classifier", fake_classifier)
    on = _result(raw)

    # Even a second opinion that flatly disagrees cannot move the verdict.
    assert on["second_opinion"]["available"] is True
    assert on["second_opinion"]["phishing_probability"] == pytest.approx(0.02)
    assert on["verdict"] == off["verdict"]
