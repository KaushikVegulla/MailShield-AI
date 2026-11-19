"""Cached threat-intelligence feed matching for analysed URLs.

Two public, keyless feeds are matched locally:

- **OpenPhish** community feed — ``https://openphish.com/feed.txt``
  (the URL redirects to the project's public GitHub mirror; the
  fetcher follows redirects). A few hundred fresh phishing URLs.
- **Phishing.Database** active links —
  ``https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt``.
  Very large (hundreds of thousands of entries, tens of MB), which is
  why it is fetched in a background thread, never inside a request.

PhishTank's full feed is deliberately NOT used: downloading it
requires a registered API key, and MailShield takes no API keys.
That is a coverage limitation and it is stated here rather than
papered over.

Design rules:

- **Fail-open.** If a feed cannot be fetched, the analysis still runs;
  the status block reports the feed as unavailable with 0 entries.
  Nothing is ever fabricated: an empty index matches nothing.
- **Lazy background refresh.** The first match request kicks off a
  background load; until it finishes, matching runs against whatever
  is already cached (initially nothing) and the status says so.
- **TTL cache.** A loaded index is reused for ``TTL_SECONDS`` and then
  refreshed in the background; a failed refresh keeps the old index.
- **Matching.** An analysed URL hits on an exact (normalised) full-URL
  match, or on a host match — except that host-only matches are
  skipped for URL shorteners and well-known shared platforms
  (github.com, google.com, netlify.app, ...), where one bad page says
  nothing about the host as a whole. Bare-IP hosts are matched as
  hosts like any other dedicated host.
"""

from __future__ import annotations

import threading
import time
import urllib.request
from urllib.parse import urlparse

FEEDS = [
    {"name": "OpenPhish", "url": "https://openphish.com/feed.txt"},
    {
        "name": "Phishing.Database",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    },
]

TTL_SECONDS = 6 * 60 * 60  # refresh a loaded index after 6 hours
FETCH_TIMEOUT = 30  # seconds per feed fetch (background thread only)
FEED_POINTS = 40  # a confirmed feed listing is strong evidence

# Hosts where a host-only match would be meaningless: shorteners hide
# destinations by design, and shared platforms host millions of
# unrelated pages. Full-URL matches still apply to these hosts.
HOST_MATCH_EXCLUSIONS = {
    # shorteners (mirrors the core list in urls.py, kept local to
    # avoid an import cycle)
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly",
    "shorturl.at", "is.gd", "tiny.cc", "ow.ly", "buff.ly", "rebrand.ly",
    "s.id", "short.io",
    # shared platforms / multi-tenant hosts
    "github.com", "github.io", "raw.githubusercontent.com",
    "google.com", "drive.google.com", "docs.google.com", "sites.google.com",
    "wordpress.com", "blogspot.com", "weebly.com", "wixsite.com",
    "netlify.app", "vercel.app", "firebaseapp.com", "web.app",
    "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
    "ipfs.io", "glitch.me", "repl.co", "herokuapp.com", "pages.dev",
    "workers.dev", "r2.dev", "blogspot.in", "tumblr.com", "medium.com",
}


def _normalise_url(url: str) -> str:
    """Lowercase scheme/host and drop a trailing slash for matching."""
    url = url.strip()
    parts = urlparse(url)
    if not parts.hostname:
        return url.lower()
    rebuilt = f"{parts.scheme.lower()}://{parts.hostname.lower()}"
    if parts.port:
        rebuilt += f":{parts.port}"
    rebuilt += parts.path or ""
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt.rstrip("/")


def parse_feed_content(text: str) -> tuple[set[str], set[str]]:
    """Parse one feed's text into (normalised URLs, hosts)."""
    urls: set[str] = set()
    hosts: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        normalised = _normalise_url(line)
        urls.add(normalised)
        host = urlparse(normalised).hostname
        if host:
            hosts.add(host)
    return urls, hosts


def _fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "MailShield-AI feed fetcher"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


class FeedIndex:
    """In-memory feed index with lazy, background, TTL-based refresh."""

    def __init__(self, fetcher=None, feeds=None, ttl: int = TTL_SECONDS):
        self._fetcher = fetcher or _fetch_text
        self._feeds = feeds if feeds is not None else FEEDS
        self._ttl = ttl
        self._lock = threading.Lock()
        self._urls: set[str] = set()
        self._hosts: set[str] = set()
        self._url_feed: dict[str, str] = {}
        self._host_feed: dict[str, str] = {}
        self._feed_status: list[dict] = [
            {"name": f["name"], "url": f["url"], "entries": 0, "status": "not_loaded", "fetched_at": None}
            for f in self._feeds
        ]
        self._loaded_at: float | None = None
        self._refreshing = False

    # -- loading ----------------------------------------------------
    def load_content(self, feed_name: str, text: str) -> int:
        """Load feed text directly (used by tests and the refresher)."""
        urls, hosts = parse_feed_content(text)
        with self._lock:
            for url in urls:
                self._urls.add(url)
                self._url_feed.setdefault(url, feed_name)
            for host in hosts:
                self._hosts.add(host)
                self._host_feed.setdefault(host, feed_name)
            for entry in self._feed_status:
                if entry["name"] == feed_name:
                    entry.update({"entries": len(urls), "status": "ok", "fetched_at": time.time()})
            self._loaded_at = time.time()
        return len(urls)

    def _refresh(self) -> None:
        try:
            for feed in self._feeds:
                try:
                    text = self._fetcher(feed["url"])
                    self.load_content(feed["name"], text)
                except Exception:
                    with self._lock:
                        for entry in self._feed_status:
                            if entry["name"] == feed["name"] and entry["status"] != "ok":
                                entry.update({"entries": 0, "status": "unavailable", "fetched_at": None})
        finally:
            with self._lock:
                self._refreshing = False

    def ensure_fresh(self) -> None:
        """Kick off a background refresh if the index is stale/empty."""
        with self._lock:
            stale = self._loaded_at is None or (time.time() - self._loaded_at) > self._ttl
            if not stale or self._refreshing:
                return
            self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()

    def refresh_now(self) -> None:
        """Synchronous refresh (startup scripts and tests)."""
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        self._refresh()

    # -- matching ---------------------------------------------------
    def match(self, url: str) -> dict | None:
        """Return a hit dict for one URL, or None."""
        normalised = _normalise_url(url)
        host = urlparse(normalised).hostname or ""
        with self._lock:
            if normalised in self._urls:
                return {"match_type": "url", "feed": self._url_feed.get(normalised), "matched": normalised}
            if host and host in self._hosts and host not in HOST_MATCH_EXCLUSIONS:
                return {"match_type": "host", "feed": self._host_feed.get(host), "matched": host}
        return None

    def status(self) -> dict:
        with self._lock:
            feeds = [dict(entry) for entry in self._feed_status]
            loaded = self._loaded_at is not None
        return {
            "available": any(f["status"] == "ok" for f in feeds),
            "loaded": loaded,
            "total_entries": sum(f["entries"] for f in feeds),
            "feeds": feeds,
            "note": (
                None
                if loaded
                else "Feed index is still loading in the background or the feeds were unreachable — no feed matching was applied to this analysis."
            ),
        }


# Process-wide index used by the API.
INDEX = FeedIndex()


def apply_feed_matches(url_analysis: dict, index: FeedIndex | None = None) -> dict:
    """Check every analysed URL against the feed index.

    Adds a ``feed_match`` flag (FEED_POINTS) to each hitting URL,
    recomputes that URL's points and the aggregate, and returns the
    feed status block for the analysis response.
    """
    idx = index if index is not None else INDEX
    idx.ensure_fresh()
    hits = []
    for entry in url_analysis.get("urls", []):
        hit = idx.match(entry["url"])
        if not hit:
            continue
        detail = (
            f"URL is listed in the {hit['feed']} phishing feed (exact URL match)."
            if hit["match_type"] == "url"
            else f"URL host ({hit['matched']}) is listed in the {hit['feed']} phishing feed."
        )
        entry["flags"].append(
            {"name": "feed_match", "status": "fail", "detail": detail, "points": FEED_POINTS, "source": "feed", "feed": hit["feed"], "match_type": hit["match_type"]}
        )
        entry["points"] = min(sum(f["points"] for f in entry["flags"]), 100)
        entry["suspicious"] = entry["points"] > 0
        hits.append({"url": entry["url"], "feed": hit["feed"], "match_type": hit["match_type"]})
    suspicious = [u for u in url_analysis.get("urls", []) if u.get("suspicious")]
    if suspicious:
        worst = max(u["points"] for u in suspicious)
        url_analysis["url_points"] = min(worst + 10 * (len(suspicious) - 1), 100)
    url_analysis["suspicious_count"] = len(suspicious)
    status = idx.status()
    status["hits"] = hits
    return status
