"""Received-timing and originating-IP geolocation tests.

Crafted headers and a mocked geolocation fetcher — no live network.
"""

import datetime
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.geo import lookup_ip
from app.core.headers import analyze_headers, analyze_received_timing
from app.core.parser import parse_email

NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=datetime.timezone.utc)


def _parsed_with_received(*stamps):
    """Build a parsed dict whose Received chain has the given stamps.

    Stamps are listed newest-first, as in a real message.
    """
    received = [
        {"raw": f"from relay{i}.example by mx.example with ESMTP; {stamp}", "ips": ["203.0.113.10"]}
        for i, stamp in enumerate(stamps)
    ]
    return {"received": received, "originating_ip": "203.0.113.10", "from": None, "authentication_results": None}


def test_clean_chain_has_no_anomalies():
    parsed = _parsed_with_received(
        "Thu, 20 Nov 2026 11:59:00 +0000",  # newest
        "Thu, 20 Nov 2026 11:58:00 +0000",  # oldest
    )
    timing = analyze_received_timing(parsed, now=NOW)
    assert timing["hop_count"] == 2
    assert timing["anomalies"] == []
    assert timing["points"] == 0
    # hops are reported oldest first
    assert timing["hops"][0]["timestamp_utc"].startswith("2026-11-20T11:58")


def test_future_dated_hop_flags():
    parsed = _parsed_with_received("Fri, 20 Nov 2037 11:59:00 +0000")
    timing = analyze_received_timing(parsed, now=NOW)
    assert [a["type"] for a in timing["anomalies"]] == ["future_dated_hop"]


def test_negative_delay_flags():
    parsed = _parsed_with_received(
        "Thu, 20 Nov 2026 10:00:00 +0000",  # newest hop stamped EARLIER than the oldest
        "Thu, 20 Nov 2026 11:00:00 +0000",
    )
    timing = analyze_received_timing(parsed, now=NOW)
    assert "negative_delay" in {a["type"] for a in timing["anomalies"]}


def test_large_gap_flags():
    parsed = _parsed_with_received(
        "Sun, 23 Nov 2026 12:00:00 +0000",
        "Thu, 20 Nov 2026 11:00:00 +0000",
    )
    timing = analyze_received_timing(parsed, now=NOW)
    assert "large_gap" in {a["type"] for a in timing["anomalies"]}


def test_timing_reaches_header_analysis_with_zero_points():
    raw = (
        "From: A <a@example.com>\n"
        "Received: from x by y; Fri, 20 Nov 2037 11:59:00 +0000\n"
        "Subject: hi\n\nbody\n"
    )
    parsed = parse_email(raw)
    result = analyze_headers(parsed)
    assert result["received_timing"]["anomalies"][0]["type"] == "future_dated_hop"
    timing_checks = [c for c in result["checks"] if c["name"] == "received_timing"]
    assert timing_checks and timing_checks[0]["points"] == 0


FAKE_GEO = {
    "status": "success", "country": "United States", "countryCode": "US",
    "regionName": "Virginia", "city": "Ashburn", "isp": "Google LLC",
    "org": "Google Public DNS", "as": "AS15169 Google LLC", "query": "8.8.8.8",
}


def test_geolocation_with_mocked_fetcher():
    result = lookup_ip("8.8.8.8", fetcher=lambda ip: FAKE_GEO)
    assert result["available"] is True
    assert result["country"] == "United States"
    assert result["city"] == "Ashburn"
    assert result["isp"] == "Google LLC"


def test_geolocation_skips_private_ips_without_fetching():
    calls = []
    result = lookup_ip("192.168.1.10", fetcher=lambda ip: calls.append(ip) or FAKE_GEO)
    assert result["available"] is False
    assert "private or reserved" in result["note"]
    assert calls == []


def test_geolocation_fail_open_on_error_and_bad_status():
    def boom(ip):
        raise TimeoutError("slow")

    result = lookup_ip("185.220.101.99", fetcher=boom)
    assert result["available"] is False
    assert "failed" in result["note"]
    result = lookup_ip("198.51.100.23", fetcher=lambda ip: {"status": "fail", "message": "reserved range"})
    assert result["available"] is False
    result = lookup_ip(None)
    assert result["available"] is False
