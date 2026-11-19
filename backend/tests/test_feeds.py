"""Threat-feed matching tests — fixture feeds only, no live network."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.feeds import FeedIndex, apply_feed_matches
from app.core.urls import analyze_urls

FIXTURE_FEED = """# fixture feed
http://185.220.101.47/login
https://evil-host.example.com/verify/account
https://bit.ly/3abcPhish
https://github.com/some-phish/page
"""


def _index(fetcher=None):
    idx = FeedIndex(fetcher=fetcher or (lambda url: FIXTURE_FEED), feeds=[{"name": "FixtureFeed", "url": "fixture://feed"}])
    idx.refresh_now()
    return idx


def test_fixture_url_hits_exact_and_host():
    idx = _index()
    hit = idx.match("http://185.220.101.47/login")
    assert hit is not None and hit["match_type"] == "url" and hit["feed"] == "FixtureFeed"
    host_hit = idx.match("https://evil-host.example.com/other/path")
    assert host_hit is not None and host_hit["match_type"] == "host"
    status = idx.status()
    assert status["available"] is True and status["total_entries"] == 4


def test_clean_url_misses():
    idx = _index()
    assert idx.match("https://www.paypal.com/signin") is None
    assert idx.match("https://cutm.ac.in/notices") is None


def test_shared_and_shortener_hosts_skip_host_match_but_not_url_match():
    idx = _index()
    # bit.ly and github.com host other people's pages — host-only must not hit
    assert idx.match("https://bit.ly/some-other-link") is None
    assert idx.match("https://github.com/unrelated/repo") is None
    # but the exact listed URLs still hit
    assert idx.match("https://bit.ly/3abcPhish")["match_type"] == "url"
    assert idx.match("https://github.com/some-phish/page")["match_type"] == "url"


def test_fail_open_when_fetch_fails():
    def boom(url):
        raise OSError("network down")

    idx = FeedIndex(fetcher=boom, feeds=[{"name": "FixtureFeed", "url": "fixture://feed"}])
    idx.refresh_now()
    status = idx.status()
    assert status["available"] is False
    assert status["total_entries"] == 0
    assert idx.match("http://185.220.101.47/login") is None


def test_apply_feed_matches_scores_and_reports():
    idx = _index()
    parsed = {"body_text": "Verify now: http://185.220.101.47/login and read https://cutm.ac.in/notices", "body_html": None}
    url_analysis = analyze_urls(parsed)
    before = {u["url"]: u["points"] for u in url_analysis["urls"]}
    status = apply_feed_matches(url_analysis, index=idx)
    by_url = {u["url"]: u for u in url_analysis["urls"]}
    hit_url = by_url["http://185.220.101.47/login"]
    feed_flags = [f for f in hit_url["flags"] if f["name"] == "feed_match"]
    assert len(feed_flags) == 1
    assert feed_flags[0]["points"] == 40 and feed_flags[0]["source"] == "feed"
    assert hit_url["points"] == before["http://185.220.101.47/login"] + 40
    assert by_url["https://cutm.ac.in/notices"]["points"] == 0
    assert status["hits"] and status["hits"][0]["feed"] == "FixtureFeed"
