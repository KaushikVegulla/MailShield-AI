"""BEC intent tests: crafted CEO fraud scores high; ordinary mail stays low."""

import pathlib

from app.core.bec import analyze_bec
from app.core.parser import parse_email

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"

CEO_FRAUD = """From: Ramesh Kumar <ramesh.kumar.ceo@gmail.com>
Reply-To: ramesh.kumar.ceo@gmail.com
To: accounts@company.example
Subject: Confidential - urgent payment

Hi,

I am in a meeting and need you to process an urgent payment today. We have
switched to a new bank account for the vendor — please use the new account
details I will send shortly and make a wire transfer before end of day.

Please keep this confidential and do not discuss this with anyone yet.
Don't call me, just handle it and confirm by email.

Regards,
Ramesh Kumar
Chief Executive Officer
"""

PLAIN_INVOICE = """From: Accounts <billing@vendor-corp.example>
To: ap@company.example
Subject: Invoice 1042 for March services

Hello,

Please find invoice 1042 for March services attached. Payment terms are
net 30 as per our agreement. Let me know if you need anything else.

Thanks,
Vendor Corp Accounts
"""


def _parsed(raw: str) -> dict:
    return parse_email(raw)


def test_ceo_fraud_scores_high_bec_risk():
    result = analyze_bec(_parsed(CEO_FRAUD))
    names = {s["name"] for s in result["signals"]}
    assert "bank_detail_change" in names
    assert "wire_payment_request" in names
    assert "payment_urgency" in names
    assert "secrecy_request" in names
    assert "executive_impersonation_context" in names
    assert result["risk_level"] == "high"
    assert all(s["evidence"] for s in result["signals"])


def test_plain_invoice_stays_low():
    result = analyze_bec(_parsed(PLAIN_INVOICE))
    assert result["risk_level"] == "low"
    assert result["bec_points"] == 0


def test_legit_samples_stay_low():
    for name in ("legit_college.eml", "legit_newsletter.eml"):
        raw = (SAMPLES / name).read_bytes()
        result = analyze_bec(parse_email(raw))
        assert result["risk_level"] == "low", (name, result)
        assert result["bec_points"] == 0, (name, result)


def test_gift_card_request_fires():
    raw = "From: Boss <boss@gmail.com>\nSubject: Quick task\n\nPlease buy gift cards worth 500 and send me the codes."
    result = analyze_bec(_parsed(raw))
    assert any(s["name"] == "gift_card_request" for s in result["signals"])
    assert result["risk_level"] in ("elevated", "high")


def test_exec_title_on_own_corporate_domain_does_not_fire_impersonation():
    raw = (
        "From: Ramesh Kumar <ramesh@company.example>\nReply-To: ramesh@company.example\n"
        "Subject: Board meeting\n\nTeam, the board meeting moves to Friday.\n\nRamesh Kumar\nChief Executive Officer\n"
    )
    result = analyze_bec(_parsed(raw))
    assert not any(s["name"] == "executive_impersonation_context" for s in result["signals"])
