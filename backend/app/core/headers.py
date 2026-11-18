"""Header forensics: SPF/DKIM/DMARC, From vs Reply-To, spoofing signals.

Every check returns a status and a human-readable detail so the dashboard
can show the evidence, not just a score. Risk points here are the *rule*
signals that the hybrid scorer (a later step) will consume.
"""

from __future__ import annotations

import re

_AUTH_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE),
}

# Points are on a 0-100 rule scale, before hybrid weighting.
POINTS = {
    "spf_fail": 25,
    "spf_softfail": 10,
    "spf_missing": 10,
    "dkim_fail": 20,
    "dkim_missing": 10,
    "dmarc_fail": 25,
    "dmarc_missing": 10,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "return_path_ip": 15,
    "no_received": 5,
}


def _auth_results(auth_raw: str | None) -> dict:
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_raw:
        return results
    for key, pattern in _AUTH_RE.items():
        match = pattern.search(auth_raw)
        if match:
            results[key] = match.group(1).lower()
    return results


def _check(name: str, status: str, detail: str, points: int = 0) -> dict:
    return {"name": name, "status": status, "detail": detail, "points": points}


def analyze_headers(parsed: dict) -> dict:
    """Run forensic checks over a parsed email (see parser.parse_email)."""
    auth = _auth_results(parsed.get("authentication_results"))
    checks: list[dict] = []

    # --- SPF ---
    spf = auth["spf"]
    if spf == "pass":
        checks.append(_check("spf", "pass", "SPF passed — sending IP is authorised for the sender domain."))
    elif spf == "fail":
        checks.append(_check("spf", "fail", "SPF failed — sending IP is NOT authorised for the sender domain. Strong spoofing signal.", POINTS["spf_fail"]))
    elif spf == "softfail":
        checks.append(_check("spf", "warn", "SPF softfail — sending IP is probably not authorised, but the domain allows a weak policy.", POINTS["spf_softfail"]))
    else:
        checks.append(_check("spf", "warn", f"No SPF pass recorded (result: {spf}). The email cannot be verified against the sender domain.", POINTS["spf_missing"]))

    # --- DKIM ---
    dkim = auth["dkim"]
    if dkim == "pass":
        checks.append(_check("dkim", "pass", "DKIM passed — the message carries a valid signature from the sender domain."))
    elif dkim == "fail":
        checks.append(_check("dkim", "fail", "DKIM failed — the domain signature is invalid or does not match the message.", POINTS["dkim_fail"]))
    else:
        checks.append(_check("dkim", "warn", f"No valid DKIM signature (result: {dkim}). Legitimate senders normally sign their mail.", POINTS["dkim_missing"]))

    # --- DMARC ---
    dmarc = auth["dmarc"]
    if dmarc == "pass":
        checks.append(_check("dmarc", "pass", "DMARC passed — From domain aligns with SPF/DKIM."))
    elif dmarc == "fail":
        checks.append(_check("dmarc", "fail", "DMARC failed — the From domain does not align with authenticated sources. Strong spoofing signal.", POINTS["dmarc_fail"]))
    else:
        checks.append(_check("dmarc", "warn", f"No DMARC pass recorded (result: {dmarc}).", POINTS["dmarc_missing"]))

    from_info = parsed.get("from") or {}
    from_domain = from_info.get("domain")

    # --- Reply-To mismatch ---
    reply_to = parsed.get("reply_to")
    if reply_to and reply_to.get("domain") and from_domain and reply_to["domain"] != from_domain:
        checks.append(_check("reply_to_mismatch", "fail", f"Reply-To domain ({reply_to['domain']}) differs from From domain ({from_domain}). Replies would go to a different domain than the visible sender.", POINTS["reply_to_mismatch"]))
    elif reply_to:
        checks.append(_check("reply_to_mismatch", "pass", "Reply-To domain matches the From domain."))

    # --- Return-Path ---
    return_path = parsed.get("return_path")
    if return_path:
        rp_raw = (return_path.get("email") or return_path.get("raw") or "")
        rp_domain_is_ip = bool(return_path.get("domain")) and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", return_path["domain"]) is not None
        if rp_domain_is_ip or (return_path.get("domain") is None and "@" in rp_raw):
            checks.append(_check("return_path", "fail", f"Return-Path uses a bare IP instead of a domain ({rp_raw}). Typical of throwaway phishing infrastructure.", POINTS["return_path_ip"]))
        elif return_path.get("domain") and from_domain and return_path["domain"] != from_domain:
            checks.append(_check("return_path", "warn", f"Return-Path domain ({return_path['domain']}) differs from From domain ({from_domain}).", POINTS["return_path_mismatch"]))
        else:
            checks.append(_check("return_path", "pass", "Return-Path aligns with the From domain."))

    # --- Received chain ---
    received = parsed.get("received") or []
    if received:
        checks.append(_check("received_chain", "info", f"{len(received)} Received hop(s) recorded. Originating IP: {parsed.get('originating_ip') or 'unknown'}."))
    else:
        checks.append(_check("received_chain", "warn", "No Received headers — the mail path cannot be traced. Common in pasted fragments, unusual in real mail.", POINTS["no_received"]))

    rule_points = sum(c["points"] for c in checks)
    spoofed = spf == "fail" or dmarc == "fail" or (
        spf in ("fail", "softfail") and bool(reply_to and from_domain and reply_to.get("domain") != from_domain)
    )

    return {
        "auth": auth,
        "from_domain": from_domain,
        "originating_ip": parsed.get("originating_ip"),
        "spoofed_sender_suspected": spoofed,
        "checks": checks,
        "rule_points": min(rule_points, 100),
    }
