"""Redirect-chain and landing-page analysis for analysed URLs.

Until now URL analysis was purely lexical — it never looked at where
a link actually goes. Phishing links routinely hide behind shorteners
and open redirectors, and the credential-harvesting page sits at the
end of the chain, so this module follows the chain server-side and
inspects the landing page.

Safety model (this module fetches attacker-controlled URLs):

- **SSRF guard:** every hop's host is resolved first and the fetch is
  refused if any resolved address is private, loopback, link-local,
  multicast or reserved. Only http/https are fetched.
- **Bounded:** at most ``MAX_URLS`` URLs per email, ``MAX_HOPS``
  redirects each, a per-URL wall-clock budget, and a response-size
  cap. No JavaScript is executed; only headers and static HTML are
  read.
- **Fail-open:** any error (DNS, timeout, TLS, refusal) is recorded
  on that URL's redirect entry and analysis continues — a failed
  fetch never blocks or fails the email analysis.

URLs that already matched a threat feed are *not* fetched: the feed
hit is already conclusive evidence, and visiting a known-bad URL adds
risk without adding information. That choice is reported in the
returned summary (``skipped_feed_matched``).

Fetching a URL can in principle tip off an attacker or burn a
one-time link; that is the accepted trade-off of the v2 design (the
research compared this with urlscan-style search-before-scan, which
needs an API key). The fetch uses a plain browser-like User-Agent and
sends no cookies and no credentials.
"""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.core.urls import BRANDS, SHORTENERS, _registrable

MAX_URLS = 5
MAX_HOPS = 5
TIMEOUT_SECONDS = 4.0
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

POINTS = {
    "redirect_cross_domain": 15,
    "shortener_expansion": 10,
    "landing_password_form": 20,
    "landing_cross_domain_form": 20,
    "landing_brand_impersonation": 20,
}

LURE_PHRASES = [
    "verify your account",
    "verify your identity",
    "sign in to your account",
    "log in to your account",
    "confirm your identity",
    "restore access",
    "account has been limited",
    "unusual activity",
]


# ---------------------------------------------------------------------------
# Transport + resolution (injectable for tests)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_transport(url: str, timeout: float) -> dict:
    """One HTTP request, no redirect following.

    Returns {status, headers (lower-cased dict), body}. Raises on
    network errors; HTTP error statuses (including 3xx, which urllib
    surfaces as HTTPError once redirects are disabled) are returned
    as normal responses.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return {
                "status": response.status,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "body": response.read(MAX_BODY_BYTES + 1),
            }
    except urllib.error.HTTPError as error:
        try:
            body = error.read(MAX_BODY_BYTES + 1)
        except Exception:
            body = b""
        return {
            "status": error.code,
            "headers": {k.lower(): v for k, v in (error.headers.items() if error.headers else [])},
            "body": body,
        }


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


def _host_is_public(host: str, resolver) -> tuple[bool, str | None]:
    """SSRF guard: True only if every resolved address is public."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            resolved = resolver(host)
        except Exception as exc:
            return False, f"DNS resolution failed: {exc}"
        if not resolved:
            return False, "DNS resolution returned no addresses"
        addresses = []
        for item in resolved:
            try:
                addresses.append(ipaddress.ip_address(item))
            except ValueError:
                return False, f"Resolver returned a non-IP value: {item!r}"
    for address in addresses:
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return False, f"host resolves to non-public address {address}"
    return True, None


# ---------------------------------------------------------------------------
# Landing-page inspection
# ---------------------------------------------------------------------------


class _LandingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_password_input = False
        self.form_actions: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag.lower() == "input" and (attributes.get("type") or "").lower() == "password":
            self.has_password_input = True
        if tag.lower() == "form":
            self.form_actions.append(attributes.get("action") or "")

    def handle_data(self, data):
        self.text_parts.append(data)


def _landing_signals(html: str, final_url: str) -> list[dict]:
    parser = _LandingParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    final_host = (urlparse(final_url).hostname or "").lower()
    final_reg = _registrable(final_host) if final_host else ""
    signals: list[dict] = []

    if parser.has_password_input:
        signals.append(
            {
                "name": "landing_password_form",
                "detail": "Landing page contains a password field — it asks for credentials.",
                "points": POINTS["landing_password_form"],
            }
        )

    for action in parser.form_actions:
        if not action:
            continue
        action_host = (urlparse(urljoin(final_url, action)).hostname or "").lower()
        if action_host and _registrable(action_host) != final_reg:
            signals.append(
                {
                    "name": "landing_cross_domain_form",
                    "detail": f"Landing page form submits to a different domain ({action_host}) than the page itself ({final_host}).",
                    "points": POINTS["landing_cross_domain_form"],
                }
            )
            break

    text = " ".join(parser.text_parts).lower()
    for brand, official in BRANDS.items():
        if brand in text and final_reg != official:
            lure = next((phrase for phrase in LURE_PHRASES if phrase in text), None)
            if parser.has_password_input or lure:
                signals.append(
                    {
                        "name": "landing_brand_impersonation",
                        "detail": f"Landing page presents the '{brand}' brand on {final_host or 'an unrelated domain'}, which is not {official}, and asks for credentials or verification.",
                        "points": POINTS["landing_brand_impersonation"],
                    }
                )
            break

    return signals


# ---------------------------------------------------------------------------
# Chain following
# ---------------------------------------------------------------------------


def follow_chain(url: str, transport=None, resolver=None) -> dict:
    """Follow one URL's redirect chain and inspect the landing page."""
    transport = transport or _default_transport
    resolver = resolver or _default_resolver
    started = time.monotonic()
    chain: list[dict] = []
    current = url
    seen: set[str] = set()

    while True:
        parts = urlparse(current)
        if parts.scheme not in ("http", "https"):
            return {"url": url, "available": False, "error": f"refused non-HTTP scheme: {parts.scheme or 'none'}", "chain": chain}
        host = (parts.hostname or "").lower()
        if not host:
            return {"url": url, "available": False, "error": "URL has no host", "chain": chain}
        public, problem = _host_is_public(host, resolver)
        if not public:
            return {"url": url, "available": False, "error": f"SSRF guard refused {host}: {problem}", "chain": chain}
        if current in seen:
            return {"url": url, "available": False, "error": "redirect loop detected", "chain": chain}
        seen.add(current)

        remaining = TIMEOUT_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            return {"url": url, "available": False, "error": "redirect budget exhausted (timeout)", "chain": chain}
        try:
            response = transport(current, timeout=remaining)
        except Exception as exc:  # fail-open: record, never raise
            return {"url": url, "available": False, "error": f"fetch failed: {type(exc).__name__}: {exc}", "chain": chain}

        status = int(response.get("status") or 0)
        headers = response.get("headers") or {}
        location = headers.get("location")
        chain.append({"url": current, "status": status})
        if status in REDIRECT_STATUSES and location:
            if len(chain) > MAX_HOPS:
                return {"url": url, "available": False, "error": f"more than {MAX_HOPS} redirects", "chain": chain}
            current = urljoin(current, location)
            continue

        body = (response.get("body") or b"")[:MAX_BODY_BYTES]
        content_type = (headers.get("content-type") or "").lower()
        signals: list[dict] = []
        if "html" in content_type or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            signals = _landing_signals(body.decode("utf-8", errors="replace"), current)
        return {
            "url": url,
            "available": True,
            "error": None,
            "chain": chain,
            "final_url": current,
            "final_status": status,
            "signals": signals,
        }


def _flag(name: str, detail: str, points: int) -> dict:
    return {"name": name, "status": "fail" if points else "warn", "detail": detail, "points": points, "source": "redirect"}


def _recompute_url_points(url_analysis: dict) -> None:
    """Re-aggregate url_points after redirect flags were added.

    Mirrors analyze_urls' aggregation: worst link in full plus 10 for
    each additional suspicious link, capped at 100.
    """
    for entry in url_analysis.get("urls", []):
        entry["points"] = min(sum(f.get("points", 0) for f in entry.get("flags", [])), 100)
        entry["suspicious"] = entry["points"] > 0
    suspicious = [e for e in url_analysis.get("urls", []) if e["suspicious"]]
    if suspicious:
        worst = max(e["points"] for e in suspicious)
        url_analysis["url_points"] = min(worst + 10 * (len(suspicious) - 1), 100)
    else:
        url_analysis["url_points"] = 0
    url_analysis["suspicious_count"] = len(suspicious)


def analyze_redirects(url_analysis: dict, transport=None, resolver=None, max_urls: int = MAX_URLS) -> dict:
    """Follow redirect chains for analysed URLs and add flags.

    Mutates ``url_analysis`` entries (adds a ``redirect`` block and any
    redirect/landing flags, then recomputes points) and returns the
    summary block for the analysis response.
    """
    checked = 0
    skipped_feed = 0
    fetched = 0
    results: list[dict] = []

    for entry in url_analysis.get("urls", []):
        if checked >= max_urls:
            break
        url = entry.get("url") or ""
        if not url.lower().startswith(("http://", "https://")):
            continue
        if any(f.get("name") == "feed_match" for f in entry.get("flags", [])):
            skipped_feed += 1
            entry["redirect"] = {"available": False, "error": "not fetched — URL already matched a threat feed", "chain": []}
            continue
        checked += 1
        outcome = follow_chain(url, transport=transport, resolver=resolver)
        entry["redirect"] = {k: v for k, v in outcome.items() if k != "signals"}
        results.append(outcome)
        if not outcome.get("available"):
            continue
        fetched += 1

        original_host = (urlparse(url).hostname or "").lower()
        final_url = outcome.get("final_url") or url
        final_host = (urlparse(final_url).hostname or "").lower()
        hops = max(len(outcome.get("chain", [])) - 1, 0)

        if original_host in SHORTENERS and hops > 0 and final_host != original_host:
            entry["flags"].append(
                _flag("shortener_expansion", f"Shortener {original_host} expands through {hops} redirect(s) to {final_host}.", POINTS["shortener_expansion"])
            )
        if final_host and original_host and _registrable(final_host) != _registrable(original_host):
            entry["flags"].append(
                _flag("redirect_cross_domain", f"Link redirects to a different domain than it claims: {original_host} -> {final_host}.", POINTS["redirect_cross_domain"])
            )
        for signal in outcome.get("signals", []):
            entry["flags"].append(_flag(signal["name"], signal["detail"], signal["points"]))

    _recompute_url_points(url_analysis)
    return {
        "available": fetched > 0 or checked == 0,
        "checked": checked,
        "fetched": fetched,
        "skipped_feed_matched": skipped_feed,
        "urls_with_chains": sum(1 for r in results if len(r.get("chain", [])) > 1),
        "note": "Redirect chains were followed server-side with SSRF guards (private/loopback targets refused), a 5-hop / 4-second budget per URL, and no JavaScript execution. URLs already matched by a threat feed were not fetched.",
    }
