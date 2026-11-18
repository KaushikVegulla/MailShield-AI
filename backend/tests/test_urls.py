"""URL analysis tests against the demo samples plus focused unit cases."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.parser import parse_email
from app.core.urls import analyze_urls, check_url

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def _load(name):
    return analyze_urls(parse_email((SAMPLES / name).read_bytes()))


def _flag_names(result_url):
    return {f["name"] for f in result_url["flags"]}


def test_paypal_sample_ip_link_with_display_mismatch():
    result = _load("phishing_paypal.eml")
    assert result["url_count"] == 1
    url = result["urls"][0]
    assert {"ip_host", "display_mismatch", "http"} <= _flag_names(url)
    # 25 ip + 25 mismatch + 10 http
    assert url["points"] == 60
    assert result["url_points"] == 60


def test_bank_sample_shortener_and_punycode():
    result = _load("phishing_bank.eml")
    assert result["url_count"] == 2
    by_host = {u["host"]: u for u in result["urls"]}
    assert "shortener" in _flag_names(by_host["bit.ly"])
    assert "display_mismatch" in _flag_names(by_host["bit.ly"])
    puny = by_host["xn--hdfcbank-secure-3we.com"]
    assert "punycode" in _flag_names(puny)
    assert "display_mismatch" in _flag_names(puny)
    # the punycode host also embeds the real brand name as a token
    assert "lookalike" in _flag_names(puny)
    # worst link 65 (20 punycode + 20 lookalike + 25 mismatch) + 10 for the second bad link
    assert result["url_points"] == 75


def test_legit_samples_have_clean_urls():
    for name in ("legit_college.eml", "legit_newsletter.eml"):
        result = _load(name)
        assert result["url_count"] == 1
        assert result["suspicious_count"] == 0
        assert result["url_points"] == 0


def test_lookalike_brand_domain():
    url = check_url({"url": "https://paypa1.com/login", "display_text": None})
    assert "lookalike" in _flag_names(url)
    url = check_url({"url": "https://hdfcbank-secure.com/kyc", "display_text": None})
    assert "lookalike" in _flag_names(url)
    # The real brand domain must not flag itself.
    url = check_url({"url": "https://www.paypal.com/signin", "display_text": None})
    assert "lookalike" not in _flag_names(url)


def test_at_sign_trick_and_suspicious_tld():
    url = check_url({"url": "https://paypal.com@evil-host.xyz/login", "display_text": None})
    names = _flag_names(url)
    assert "at_sign" in names
    assert "suspicious_tld" in names


def test_no_links_is_clean():
    result = analyze_urls({"body_text": "Hello, no links here.", "body_html": None})
    assert result["url_count"] == 0
    assert result["url_points"] == 0
