"""Hybrid scoring tests: unit cases plus the four demo samples end-to-end."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.anomaly import analyze_anomaly
from app.core.headers import analyze_headers
from app.core.parser import parse_email
from app.core.scoring import combine_scores, score_email
from app.core.urls import analyze_urls
from app.ml.predict import predict_phishing

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def _verdict_for(name):
    parsed = parse_email((SAMPLES / name).read_bytes())
    return score_email(
        parsed,
        analyze_headers(parsed),
        analyze_urls(parsed),
        predict_phishing(parsed),
        analyze_anomaly(parsed),
    )


def test_anomaly_fires_on_pressure_language():
    parsed = parse_email(
        "Subject: URGENT action required\n\nVerify immediately within 24 hours. "
        "Enter your password and card details or your account will be closed."
    )
    result = analyze_anomaly(parsed)
    categories = {s["category"] for s in result["signals"]}
    assert categories == {"urgency", "threat", "credential_request"}
    assert result["anomaly_points"] > 60


def test_anomaly_quiet_on_plain_mail():
    parsed = parse_email("Subject: Exam seating\n\nDear students, please check your room number.")
    assert analyze_anomaly(parsed)["anomaly_points"] == 0


def test_combine_renormalises_without_ml():
    result = combine_scores(header_points=0, url_points=0, ml_points=None, anomaly_points=0)
    assert result["score"] == 0
    assert result["verdict"] == "likely_legitimate"
    assert "ml" not in result["weights_used"]


def test_combine_rule_floor():
    # Both rule channels maximal: rule score 100 -> floor keeps it deep red
    # even if ML and anomaly were somehow zero.
    result = combine_scores(header_points=100, url_points=100, ml_points=0, anomaly_points=0)
    assert result["rule_floor_applied"] is True
    assert result["score"] == 85
    assert result["verdict"] == "phishing"


def test_sample_verdicts():
    paypal = _verdict_for("phishing_paypal.eml")
    assert paypal["verdict"] == "phishing" and paypal["score"] >= 75

    bank = _verdict_for("phishing_bank.eml")
    assert bank["verdict"] == "phishing" and bank["score"] >= 75

    # The ML model alone over-scores these short modern legit samples;
    # the hybrid verdict must still land them in the legitimate band
    # because their headers and URLs are completely clean.
    for name in ("legit_college.eml", "legit_newsletter.eml"):
        legit = _verdict_for(name)
        assert legit["verdict"] == "likely_legitimate" and legit["score"] < 40, (name, legit)


def test_reasons_are_explainable():
    verdict = _verdict_for("phishing_paypal.eml")
    sources = {r["source"] for r in verdict["reasons"]}
    assert {"headers", "url", "anomaly"} <= sources
    assert all(r["detail"] for r in verdict["reasons"])
