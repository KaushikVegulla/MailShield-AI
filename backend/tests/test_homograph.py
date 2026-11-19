"""Homograph / confusable domain tests (UTS #39 skeletons)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.homograph import analyse_domain, skeleton
from app.core.urls import BRANDS, _registrable, check_url

CYRILLIC_A = "а"  # U+0430, looks like Latin "a"
CYRILLIC_P = "р"  # U+0440, looks like Latin "p"
CYRILLIC_O = "о"  # U+043E, looks like Latin "o"


def _flag_names(result_url):
    return {f["name"] for f in result_url["flags"]}


def test_cyrillic_lookalike_paypal_flags():
    host = f"p{CYRILLIC_A}ypal.com"
    url = check_url({"url": f"https://{host}/login", "display_text": None})
    assert "homograph" in _flag_names(url)
    flag = next(f for f in url["flags"] if f["name"] == "homograph")
    assert flag["points"] == 25
    assert "paypal.com" in flag["detail"]


def test_punycode_encoded_lookalike_flags():
    host = f"p{CYRILLIC_A}ypal.com"
    puny = host.encode("idna").decode("ascii")
    assert puny.startswith("xn--")
    url = check_url({"url": f"https://{puny}/login", "display_text": None})
    assert "homograph" in _flag_names(url)


def test_real_brand_domain_never_flags():
    for url_text in ("https://www.paypal.com/signin", "https://paypal.com/", "https://github.com/login"):
        url = check_url({"url": url_text, "display_text": None})
        assert "homograph" not in _flag_names(url), url_text
        assert "mixed_script" not in _flag_names(url), url_text


def test_normal_non_brand_domain_does_not_flag():
    url = check_url({"url": "https://cutm.ac.in/notices", "display_text": None})
    assert "homograph" not in _flag_names(url)
    assert "mixed_script" not in _flag_names(url)
    assert url["points"] == 0


def test_mixed_script_without_brand_match_warns():
    host = f"g{CYRILLIC_O}{CYRILLIC_O}gle-example.com"  # not a brand skeleton
    result = analyse_domain(host, _registrable, BRANDS)
    assert result["mixed_script"] is True
    assert result["imitates"] is None
    url = check_url({"url": f"https://{host}/", "display_text": None})
    assert "mixed_script" in _flag_names(url)


def test_skeleton_maps_confusables_and_fullwidth():
    assert skeleton(f"p{CYRILLIC_A}yp{CYRILLIC_A}l.com") == "paypal.com"
    assert skeleton("ｐａｙｐａｌ.com") == "paypal.com"
    assert skeleton("paypal.com") == "paypal.com"
