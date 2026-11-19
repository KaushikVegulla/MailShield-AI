"""DMARC alignment, ARC summary, evidence hashing and PDF forensic
section tests (alignment helpers, defanging, IOCs, ATT&CK mapping)."""

import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.core.headers import analyze_headers, evaluate_dmarc_alignment, summarize_arc
from app.core.parser import parse_email
from app.main import app
from app.services.report import attck_mapping, collect_iocs, defang

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
client = TestClient(app)


def _parsed(auth_results, from_domain="example.com", mailfrom_domain=None, return_path_domain=None):
    return {
        "authentication_results": auth_results,
        "from": {"raw": f"Sender <sender@{from_domain}>", "email": f"sender@{from_domain}", "domain": from_domain},
        "reply_to": None,
        "return_path": (
            {"raw": f"<bounce@{return_path_domain}>", "email": f"bounce@{return_path_domain}", "domain": return_path_domain}
            if return_path_domain
            else None
        ),
        "received": [{"raw": "from mail.example.com [192.0.2.1]", "ips": ["192.0.2.1"]}],
        "originating_ip": "192.0.2.1",
        "arc_authentication_results": [],
        "arc_message_signature": [],
        "arc_seal": [],
    }


def test_alignment_pass_via_spf_and_dkim():
    parsed = _parsed(
        "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )
    result = analyze_headers(parsed)
    alignment = result["dmarc_alignment"]
    assert alignment["spf"]["aligned"] is True
    assert alignment["dkim"]["aligned"] is True
    assert alignment["dmarc"]["evaluated_result"] == "pass"
    assert alignment["dmarc"]["aligned_via"] in ("spf", "dkim")
    check = {c["name"]: c for c in result["checks"]}["dmarc_alignment"]
    assert check["status"] == "pass" and check["points"] == 0


def test_unaligned_pass_is_dmarc_fail():
    # SPF passes — but for an unrelated relay domain. That is not DMARC.
    parsed = _parsed(
        "mx.example.com; spf=pass smtp.mailfrom=evil-relay.net; dkim=none; dmarc=none header.from=example.com",
        return_path_domain="evil-relay.net",
    )
    alignment = evaluate_dmarc_alignment(parsed, {"spf": "pass", "dkim": "none", "dmarc": "none"})
    assert alignment["spf"]["aligned"] is False
    assert alignment["dkim"]["aligned"] is False
    assert alignment["dmarc"]["evaluated_result"] == "fail"
    result = analyze_headers(parsed)
    check = {c["name"]: c for c in result["checks"]}["dmarc_alignment"]
    assert check["status"] == "fail"


def test_relaxed_alignment_allows_subdomains():
    parsed = _parsed(
        "mx.example.com; spf=pass smtp.mailfrom=bounce.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )
    alignment = evaluate_dmarc_alignment(parsed, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
    assert alignment["spf"]["aligned"] is True
    assert alignment["dkim"]["aligned"] is True


def test_alignment_unknown_without_auth_results():
    parsed = _parsed(None)
    alignment = evaluate_dmarc_alignment(parsed, {"spf": "none", "dkim": "none", "dmarc": "none"})
    assert alignment["dmarc"]["evaluated_result"] == "unknown"


def test_arc_chain_summary_from_raw_email():
    raw = (
        "From: Sender <sender@example.com>\r\n"
        "Subject: Forwarded message\r\n"
        "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.org; s=arc; b=abc\r\n"
        "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=arc; bh=xyz; b=def\r\n"
        "ARC-Authentication-Results: i=1; mx.example.org; spf=pass smtp.mailfrom=example.com\r\n"
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n"
        "\r\n"
        "Hello.\r\n"
    )
    parsed = parse_email(raw)
    arc = summarize_arc(parsed)
    assert arc["present"] is True
    assert arc["seal_count"] == 1
    assert arc["message_signature_count"] == 1
    assert arc["authentication_results_count"] == 1
    assert arc["instances"] == [1]
    assert arc["chain_validation"] == "none"
    result = analyze_headers(parsed)
    names = {c["name"] for c in result["checks"]}
    assert "arc_chain" in names


def test_samples_alignment_matches_receiver_result():
    for name, expected in (
        ("phishing_paypal.eml", "fail"),
        ("phishing_bank.eml", "fail"),
        ("legit_college.eml", "pass"),
        ("legit_newsletter.eml", "pass"),
    ):
        parsed = parse_email((SAMPLES / name).read_bytes())
        alignment = analyze_headers(parsed)["dmarc_alignment"]
        assert alignment["dmarc"]["evaluated_result"] == expected, name


def test_evidence_hash_in_analysis_response():
    raw = (SAMPLES / "phishing_paypal.eml").read_text()
    response = client.post("/analyze/email", json={"raw": raw})
    assert response.status_code == 200
    body = response.json()
    evidence = body["evidence"]
    assert evidence["email_sha256"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert evidence["email_size_bytes"] == len(raw.encode("utf-8"))
    assert evidence["tool"] == "MailShield AI"
    assert body["qr_analysis"]["available"] in (True, False)


def test_defang():
    assert defang("http://185.220.101.47/login") == "hxxp://185[.]220[.]101[.]47/login"
    assert defang("https://www.paypal.com/signin") == "hxxps://www[.]paypal[.]com/signin"


def test_iocs_and_attck_for_paypal_sample():
    raw = (SAMPLES / "phishing_paypal.eml").read_text()
    analysis = client.post("/analyze/email", json={"raw": raw}).json()
    iocs = collect_iocs(analysis)
    values = {(i["type"], i["value"]) for i in iocs}
    assert ("ip", "185[.]220[.]101[.]47") in values
    assert any(kind == "url" and "185[.]220[.]101[.]47" in value for kind, value in values)
    mapping = attck_mapping(analysis)
    assert [m["id"] for m in mapping] == ["T1566.002"]  # links, no attachments


def test_attck_attachment_mapping_only_with_attachment():
    analysis = {
        "parsed": {"attachments": [{"filename": "invoice.pdf.exe", "size_bytes": 10, "sha256": "x"}], "originating_ip": None},
        "url_analysis": {"urls": []},
    }
    mapping = attck_mapping(analysis)
    assert [m["id"] for m in mapping] == ["T1566.001"]
    empty = {"parsed": {"attachments": [], "originating_ip": None}, "url_analysis": {"urls": []}}
    assert attck_mapping(empty) == []
