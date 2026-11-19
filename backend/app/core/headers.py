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


def _org_domain(domain: str | None) -> str | None:
    """Organisational (registrable) domain, for relaxed alignment.

    Same heuristic as the URL analyser: last two labels, or three for
    co/ac/gov/org/net second levels under a two-letter country TLD.
    """
    if not domain:
        return None
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _auth_segments(auth_raw: str | None) -> list[dict]:
    """Split an Authentication-Results value into per-method segments.

    Each segment: the method result plus its properties, e.g.
    ``spf=pass smtp.mailfrom=example.com`` or
    ``dkim=pass header.d=example.com``. Parenthesised comments are
    dropped first so property parsing is not confused by free text.
    """
    if not auth_raw:
        return []
    cleaned = re.sub(r"\([^)]*\)", " ", auth_raw)
    segments = []
    for chunk in cleaned.split(";")[1:]:  # first chunk is the authserv-id
        match = re.match(r"\s*(\w+)=(\w+)", chunk)
        if not match:
            continue
        props = dict(re.findall(r"(\w+(?:\.\w+)*)=([^\s;]+)", chunk))
        segments.append({"method": match.group(1).lower(), "result": match.group(2).lower(), "props": props})
    return segments


def evaluate_dmarc_alignment(parsed: dict, auth: dict) -> dict:
    """Evaluate DMARC the way RFC 7489/9989 defines it: alignment.

    SPF and DKIM each authenticate an identity that is *not* necessarily
    the visible From domain. DMARC passes only when at least one
    mechanism both passes and is aligned with the From domain (relaxed
    alignment = same organisational domain). A bare "spf=pass" for an
    unrelated domain is not a DMARC pass, which is why this evaluation
    sits alongside the receiver's own dmarc= result.
    """
    from_domain = (parsed.get("from") or {}).get("domain")
    from_org = _org_domain(from_domain)
    segments = _auth_segments(parsed.get("authentication_results"))

    spf_identity = None
    dkim_signing: list[str] = []
    policy = None
    for segment in segments:
        props = segment["props"]
        if segment["method"] == "spf" and spf_identity is None:
            spf_identity = props.get("smtp.mailfrom") or props.get("smtp.helo")
        if segment["method"] == "dkim" and segment["result"] == "pass":
            d = props.get("header.d")
            if d and d not in dkim_signing:
                dkim_signing.append(d)
        if segment["method"] == "dmarc":
            raw_policy = props.get("p") or props.get("policy.dmarc")
            if raw_policy and raw_policy.lower() in ("none", "quarantine", "reject"):
                policy = raw_policy.lower()
    if spf_identity is None:
        return_path = parsed.get("return_path") or {}
        spf_identity = return_path.get("domain")

    spf_aligned = bool(
        auth["spf"] == "pass" and spf_identity and from_org and _org_domain(spf_identity) == from_org
    )
    dkim_aligned = bool(
        auth["dkim"] == "pass" and from_org and any(_org_domain(d) == from_org for d in dkim_signing)
    )

    if spf_aligned:
        evaluated, via = "pass", "spf"
    elif dkim_aligned:
        evaluated, via = "pass", "dkim"
    elif auth["spf"] == "none" and auth["dkim"] == "none":
        evaluated, via = "unknown", None
    else:
        evaluated, via = "fail", None

    return {
        "from_domain": from_domain,
        "spf": {"result": auth["spf"], "identity_domain": spf_identity, "aligned": spf_aligned},
        "dkim": {"result": auth["dkim"], "signing_domains": dkim_signing, "aligned": dkim_aligned},
        "dmarc": {
            "receiver_result": auth["dmarc"],
            "evaluated_result": evaluated,
            "aligned_via": via,
            "policy": policy,
            "policy_note": (
                f"Domain policy published in the authentication results: p={policy}."
                if policy
                else "No DMARC policy (p=) was present in the Authentication-Results header, so the domain's published policy is not shown here."
            ),
        },
        "mode": "relaxed",
    }


def summarize_arc(parsed: dict) -> dict:
    """Summarise the ARC (RFC 8617) chain, if the message carries one.

    ARC lets intermediaries (forwarders, mailing lists) seal the
    authentication results they saw, so a receiver can still judge a
    message whose SPF/DKIM broke in transit. This is a presence and
    structure summary only — seal signatures are not verified here.
    """
    seals = parsed.get("arc_seal") or []
    signatures = parsed.get("arc_message_signature") or []
    auth_results = parsed.get("arc_authentication_results") or []
    instances = sorted({int(m) for entry in seals for m in re.findall(r"\bi=(\d+)", entry)})
    cv = None
    for entry in reversed(seals):
        match = re.search(r"\bcv=(\w+)", entry)
        if match:
            cv = match.group(1).lower()
            break
    return {
        "present": bool(seals or signatures or auth_results),
        "seal_count": len(seals),
        "message_signature_count": len(signatures),
        "authentication_results_count": len(auth_results),
        "instances": instances,
        "chain_validation": cv,
        "note": "ARC seal signatures are summarised, not cryptographically verified.",
    }


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

    # --- DMARC alignment (evaluated, not just the receiver's result) ---
    # Informational: 0 points. The receiver's spf/dkim/dmarc results are
    # already scored above; this check explains *why* DMARC passes or
    # fails — alignment — without double-counting the same evidence.
    alignment = evaluate_dmarc_alignment(parsed, auth)
    dmarc_eval = alignment["dmarc"]["evaluated_result"]
    if dmarc_eval == "pass":
        checks.append(_check("dmarc_alignment", "pass", f"DMARC alignment: {alignment['dmarc']['aligned_via'].upper()} passes and its identity aligns with the From domain ({from_domain}) under relaxed alignment. {alignment['dmarc']['policy_note']}"))
    elif dmarc_eval == "fail":
        checks.append(_check("dmarc_alignment", "fail", f"DMARC alignment: neither SPF nor DKIM both passes and aligns with the From domain ({from_domain}). SPF identity: {alignment['spf']['identity_domain'] or 'unknown'} (result {alignment['spf']['result']}); DKIM signing domains: {', '.join(alignment['dkim']['signing_domains']) or 'none'} (result {alignment['dkim']['result']}). A mechanism passing for an unrelated domain does not satisfy DMARC."))
    else:
        checks.append(_check("dmarc_alignment", "warn", "DMARC alignment cannot be evaluated — no SPF or DKIM result was recorded in the authentication results."))

    # --- ARC chain ---
    arc = summarize_arc(parsed)
    if arc["present"]:
        checks.append(_check("arc_chain", "info", f"ARC chain present: {arc['seal_count']} seal(s), {arc['message_signature_count']} message signature(s), chain validation (cv) = {arc['chain_validation'] or 'not stated'}. ARC preserves earlier authentication results across forwarders; seals are summarised here, not verified."))

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
        "dmarc_alignment": alignment,
        "arc": arc,
    }
