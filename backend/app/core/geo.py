"""Originating-IP geolocation via the keyless ip-api.com free tier.

One passive lookup per public IP, cached in memory for the life of
the process. The free endpoint is plain HTTP and rate-limited
(45 requests/minute per source IP); the cache keeps repeat analyses
of the same sender from spending that budget.

Fail-open by design: any error, timeout (~2s), non-success status or
private/reserved address yields an ``available: False`` block and
never blocks or fails the analysis. Geolocation is context for the
analyst (a login alert from an unexpected country matters), never
scoring evidence by itself — it carries 0 points.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request

TIMEOUT = 2.0
FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,query"

_cache: dict[str, dict] = {}


def _fetch(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields={FIELDS}"
    request = urllib.request.Request(url, headers={"User-Agent": "MailShield-AI"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def lookup_ip(ip: str | None, fetcher=None) -> dict:
    """Geolocate one IP; returns an available/unavailable block."""
    if not ip:
        return {"available": False, "ip": None, "note": "No originating IP was found in the Received chain."}
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return {"available": False, "ip": ip, "note": f"'{ip}' is not a valid IP address."}
    if not parsed.is_global:
        return {"available": False, "ip": ip, "note": "Originating IP is private or reserved — geolocation does not apply and no lookup was made."}
    if ip in _cache:
        return _cache[ip]
    try:
        data = (fetcher or _fetch)(ip)
    except Exception as exc:  # fail-open: never break the analysis
        return {"available": False, "ip": ip, "note": f"Geolocation lookup failed ({type(exc).__name__}) — analysis continued without it."}
    if not isinstance(data, dict) or data.get("status") != "success":
        message = data.get("message") if isinstance(data, dict) else "unexpected response"
        return {"available": False, "ip": ip, "note": f"Geolocation service reported: {message}."}
    result = {
        "available": True,
        "ip": ip,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
        "source": "ip-api.com (free tier)",
        "note": None,
    }
    _cache[ip] = result
    return result
