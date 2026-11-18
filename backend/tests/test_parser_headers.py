"""Parser + header forensics tests against the demo sample emails."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.headers import analyze_headers
from app.core.parser import parse_email

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def _load(name):
    return parse_email((SAMPLES / name).read_bytes())


def test_phishing_paypal_fails_auth_and_is_spoofed():
    parsed = _load("phishing_paypal.eml")
    result = analyze_headers(parsed)
    assert parsed["subject"].startswith("URGENT")
    assert parsed["from"]["domain"] == "paypa1-secure-login.com"
    assert parsed["originating_ip"] == "185.220.101.47"
    assert result["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert result["spoofed_sender_suspected"] is True
    # spf fail 25 + dkim missing 10 + dmarc fail 25 + return-path IP 15
    assert result["rule_points"] == 75


def test_phishing_bank_reply_to_mismatch():
    parsed = _load("phishing_bank.eml")
    result = analyze_headers(parsed)
    assert result["auth"]["spf"] == "softfail"
    names = {c["name"]: c["status"] for c in result["checks"]}
    assert names["reply_to_mismatch"] == "fail"
    assert result["rule_points"] >= 45


def test_legit_college_passes_clean():
    parsed = _load("legit_college.eml")
    result = analyze_headers(parsed)
    assert result["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert result["spoofed_sender_suspected"] is False
    assert result["rule_points"] == 0
    assert parsed["from"]["domain"] == "cutm.ac.in"


def test_legit_newsletter_passes_clean():
    parsed = _load("legit_newsletter.eml")
    result = analyze_headers(parsed)
    assert result["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert result["rule_points"] == 0


def test_pasted_body_only_text_does_not_crash():
    parsed = parse_email("Win a prize now, click here!")
    assert parsed["body_text"] == "Win a prize now, click here!"
    result = analyze_headers(parsed)
    assert result["auth"]["spf"] == "none"
