"""URL analysis: extraction and malicious-link checks.

Links are extracted from HTML anchors (keeping their display text) and
from plain-text bodies. Each link is checked for the classic phishing
tells: IP hosts, shorteners, punycode, look-alike brand domains,
display-text vs href mismatch, plain HTTP, and suspicious TLDs.

No network calls are made — analysis is purely lexical, so it is fast,
deterministic, and safe to run on malicious links.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
DOMAIN_IN_TEXT_RE = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9-]+\.[a-z]{2,})(?:/[^\s]*)?", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly",
    "shorturl.at", "is.gd", "tiny.cc", "ow.ly", "buff.ly", "rebrand.ly",
    "s.id", "short.io",
}

SUSPICIOUS_TLDS = {"xyz", "top", "click", "loan", "men", "party", "science", "trade", "webcam", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "work", "live", "fun"}

# Brand name -> official domain. Used only for look-alike detection.
BRANDS = {
    "paypal": "paypal.com",
    "hdfcbank": "hdfcbank.com",
    "sbi": "sbi.co.in",
    "icicibank": "icicibank.com",
    "github": "github.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "cutm": "cutm.ac.in",
}

POINTS = {
    "ip_host": 25,
    "display_mismatch": 25,
    "punycode": 20,
    "lookalike": 20,
    "at_sign": 20,
    "shortener": 15,
    "http": 10,
    "suspicious_tld": 10,
    "subdomains": 5,
    "long_url": 5,
}


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href
                self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append({"url": self._href, "display_text": "".join(self._text).strip() or None})
            self._href = None
            self._text = []


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _lookalike_brand(host: str) -> str | None:
    """Return the official brand domain this host imitates, if any."""
    registrable = _registrable(host)
    for brand, official in BRANDS.items():
        if registrable == official:
            return None
    tokens = re.split(r"[.\-_]", host)
    for brand, official in BRANDS.items():
        for token in tokens:
            if not token:
                continue
            if token == brand and registrable != official:
                return official
            if len(token) >= 4 and token != brand and _levenshtein(token, brand) <= 1 and abs(len(token) - len(brand)) <= 1:
                return official
    return None


def extract_urls(parsed: dict) -> list[dict]:
    """Extract deduplicated links, preserving anchor display text."""
    found: dict[str, dict] = {}

    html = parsed.get("body_html")
    if html:
        parser = _AnchorParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        for link in parser.links:
            url = link["url"].strip()
            if url.lower().startswith(("http://", "https://")):
                found.setdefault(url, {"url": url, "display_text": link["display_text"]})

    text = parsed.get("body_text")
    if text:
        for match in URL_RE.findall(text):
            url = match.rstrip(".,;")
            found.setdefault(url, {"url": url, "display_text": None})

    return list(found.values())


def _flag(name: str, status: str, detail: str, points: int = 0) -> dict:
    return {"name": name, "status": status, "detail": detail, "points": points}


def check_url(link: dict) -> dict:
    url = link["url"]
    display_text = link.get("display_text")
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    flags: list[dict] = []

    is_ip = bool(IP_HOST_RE.match(host))
    if is_ip:
        flags.append(_flag("ip_host", "fail", "Link host is a bare IP address instead of a domain — legitimate services do not send login links like this.", POINTS["ip_host"]))

    if host in SHORTENERS:
        flags.append(_flag("shortener", "warn", f"URL shortener ({host}) hides the real destination.", POINTS["shortener"]))

    if "xn--" in host:
        flags.append(_flag("punycode", "fail", "Punycode domain (xn--) — used to disguise look-alike internationalised domains.", POINTS["punycode"]))

    if "@" in parts.netloc:
        flags.append(_flag("at_sign", "fail", "URL contains '@' in the authority — browsers ignore everything before it, hiding the real host.", POINTS["at_sign"]))

    official = _lookalike_brand(host) if host and not is_ip else None
    if official:
        flags.append(_flag("lookalike", "fail", f"Domain imitates {official} but is not {official} — typosquatting / look-alike domain.", POINTS["lookalike"]))

    if display_text:
        text_match = DOMAIN_IN_TEXT_RE.search(display_text)
        if text_match:
            shown = text_match.group(1).lower()
            shown_reg = _registrable(shown)
            host_reg = host if is_ip else _registrable(host)
            if shown_reg != host_reg:
                flags.append(_flag("display_mismatch", "fail", f"Link text shows '{shown}' but the link actually goes to '{host}'.", POINTS["display_mismatch"]))

    if parts.scheme == "http":
        flags.append(_flag("http", "warn", "Plain HTTP link — no encryption, and unusual for a login or verification page.", POINTS["http"]))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS and not is_ip:
        flags.append(_flag("suspicious_tld", "warn", f"Top-level domain .{tld} is heavily abused for disposable phishing sites.", POINTS["suspicious_tld"]))

    if host and not is_ip and host.count(".") >= 3:
        flags.append(_flag("subdomains", "warn", "Many subdomains — often used to pad a trusted-looking name in front of the real domain.", POINTS["subdomains"]))

    if len(url) > 75:
        flags.append(_flag("long_url", "warn", "Unusually long URL, which can hide the real destination.", POINTS["long_url"]))

    points = min(sum(f["points"] for f in flags), 100)
    return {
        "url": url,
        "display_text": display_text,
        "source": link.get("source") or "body",
        "host": host or None,
        "scheme": parts.scheme or None,
        "flags": flags,
        "points": points,
        "suspicious": points > 0,
    }


def analyze_urls(parsed: dict, extra_links: list[dict] | None = None) -> dict:
    """Analyse every link in a parsed email.

    ``extra_links`` are links found outside the body text — currently
    URLs decoded from QR codes (see app.core.qr), each carrying
    ``source: "qr"``. They are checked and scored exactly like body
    links; a URL already present as a body link is not counted twice.

    Aggregate: the worst link scores in full, plus 10 points for each
    additional suspicious link, capped at 100 — one bad link is already
    serious; several independent bad links are worse.
    """
    results = [check_url(link) for link in extract_urls(parsed)]
    known = {r["url"] for r in results}
    for link in extra_links or []:
        if link.get("url") and link["url"] not in known:
            results.append(check_url(link))
            known.add(link["url"])
    suspicious = [r for r in results if r["suspicious"]]
    if suspicious:
        worst = max(r["points"] for r in suspicious)
        total = min(worst + 10 * (len(suspicious) - 1), 100)
    else:
        total = 0
    return {
        "urls": results,
        "url_count": len(results),
        "suspicious_count": len(suspicious),
        "url_points": total,
    }
