"""Anomaly signals: social-engineering language and attachment risk.

These are behavioural signals, distinct from header/URL rules and from
the ML text classifier: pressure language, threats, and requests for
credentials or sensitive data — the human-manipulation layer of a
phishing email. Each matched phrase is reported so the analyst can
see exactly what fired.
"""

from __future__ import annotations

import re

URGENCY = [
    "urgent",
    "immediately",
    "within 24 hours",
    "within 24hrs",
    "act now",
    "action required",
    "as soon as possible",
    "final warning",
    "expires soon",
    "last chance",
]

THREATS = [
    "account will be closed",
    "account will be frozen",
    "account will be suspended",
    "permanently closed",
    "permanently deleted",
    "will be terminated",
    "legal action",
    "account has been limited",
    "account is limited",
]

CREDENTIAL_REQUESTS = [
    "enter your password",
    "your password",
    "card details",
    "credit card number",
    "debit card",
    "bank details",
    "account number",
    "one time password",
    "otp",
    "cvv",
    "pin number",
    "kyc update",
    "update your kyc",
    "social security",
]

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".html", ".htm", ".zip", ".rar", ".jar", ".msi", ".com"}

CATEGORY_POINTS = {"urgency": 12, "threat": 15, "credential_request": 18}
CATEGORY_CAPS = {"urgency": 36, "threat": 30, "credential_request": 36}


def _text_of(parsed: dict) -> str:
    html_text = re.sub(r"<[^>]+>", " ", parsed.get("body_html") or "")
    return " ".join([parsed.get("subject") or "", parsed.get("body_text") or "", html_text]).lower()


def _hits(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in text]


def analyze_anomaly(parsed: dict, score_attachments: bool = True) -> dict:
    """Behavioural signals for one parsed email.

    ``score_attachments=False`` skips the filename-level attachment
    risk below: attachment triage (core/attachments.py) scores that
    evidence more richly, and the API uses this flag so an attachment
    is never scored twice for the same fact.
    """
    text = _text_of(parsed)
    signals: list[dict] = []
    score = 0

    for category, phrases in (
        ("urgency", URGENCY),
        ("threat", THREATS),
        ("credential_request", CREDENTIAL_REQUESTS),
    ):
        hits = _hits(text, phrases)
        if hits:
            points = min(CATEGORY_POINTS[category] * len(hits), CATEGORY_CAPS[category])
            score += points
            signals.append(
                {
                    "category": category,
                    "matched": hits,
                    "points": points,
                    "detail": f"{category.replace('_', ' ').title()} language detected: {', '.join(hits)}.",
                }
            )

    for attachment in (parsed.get("attachments") or []) if score_attachments else []:
        filename = (attachment.get("filename") or "").lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        # double extension like invoice.pdf.exe
        double_ext = len(filename.split(".")) >= 3 and ext in RISKY_EXTENSIONS
        if ext in RISKY_EXTENSIONS or double_ext:
            points = 40
            score += points
            signals.append(
                {
                    "category": "risky_attachment",
                    "matched": [attachment.get("filename")],
                    "points": points,
                    "detail": f"Risky attachment type: {attachment.get('filename')} — executable or archive attachments are a common malware delivery route.",
                }
            )

    return {"anomaly_points": min(score, 100), "signals": signals}
