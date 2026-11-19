"""Business email compromise (BEC) / payment-fraud intent detection.

BEC is the costliest email crime in the FBI IC3 figures and it
usually carries *no* malicious link or attachment — the payload is a
request: change the bank details, wire the payment, buy gift cards,
move a payroll deposit, keep it quiet. Header and URL analysis see
almost nothing, so this module reads the *intent* of the message:
subject + body, in the context of who sent it.

Signals are deliberately conservative, phrase-level and explainable —
every fired signal carries the matched snippet as evidence. Points
ride the anomaly weight of the hybrid score (like attachment triage),
capped so BEC evidence alone cannot manufacture a verdict; it
compounds with whatever else the message shows.

Scope limit, stated plainly: a stateless analyser sees one message,
not a mailbox. It cannot know whether this sender has ever emailed
the recipient before, whether this thread is a hijack, or whether the
requested account change matches a real vendor — signals are reported
as "present in this message", nothing more.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "proton.me", "protonmail.com", "icloud.com", "aol.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

EXEC_TITLES = [
    "chief executive officer", "ceo", "chief financial officer", "cfo",
    "managing director", "company director", "finance director",
]

# (signal name, points, [phrases]) — phrases are matched case-insensitively
# against subject + body. Payment-context phrases are specific on purpose:
# generic urgency is the anomaly module's job, not this one's.
SIGNALS: list[tuple[str, int, list[str]]] = [
    (
        "bank_detail_change",
        25,
        [
            "new bank account", "updated bank details", "bank details have changed",
            "change of bank account", "new account details", "updated payment details",
            "change our bank", "new remittance account", "updated account details",
        ],
    ),
    (
        "payroll_diversion",
        25,
        [
            "change my direct deposit", "update my direct deposit",
            "new bank account for my salary", "change my payroll",
            "update my payroll bank", "divert my salary",
        ],
    ),
    (
        "gift_card_request",
        25,
        ["gift card", "gift cards", "steam card", "google play card", "itunes card"],
    ),
    (
        "wire_payment_request",
        20,
        [
            "wire transfer", "wire the payment", "wire the funds",
            "transfer the funds", "make the wire", "send a wire",
        ],
    ),
    (
        "payment_urgency",
        10,
        [
            "urgent payment", "payment urgently", "transfer today",
            "pay today", "before end of day", "process this payment immediately",
            "pay this invoice today", "settle this invoice urgently",
        ],
    ),
    (
        "secrecy_request",
        15,
        [
            "keep this confidential", "keep this between us", "do not discuss",
            "don't call", "do not call", "handle this discreetly",
            "on a confidential basis", "do not email", "don't email",
            "keep it confidential", "treat this as confidential",
        ],
    ),
    (
        "otp_credential_request",
        15,
        [
            "send me the otp", "share the otp", "share your verification code",
            "send me the verification code", "provide your password",
            "share your password", "send me your login",
        ],
    ),
]

BEC_POINT_CAP = 60


def _domain_of(address) -> str:
    """Domain of a sender field — the parser stores addresses as
    {raw, name, email, domain} dicts; plain strings also work."""
    if not address:
        return ""
    if isinstance(address, dict):
        if address.get("domain"):
            return str(address["domain"]).lower()
        address = address.get("email") or address.get("raw") or ""
    email = parseaddr(str(address))[1] or str(address)
    return email.rsplit("@", 1)[-1].strip().lower().strip("<>") if "@" in email else ""


def _snippet(text: str, start: int, end: int) -> str:
    lo = max(0, start - 40)
    hi = min(len(text), end + 40)
    snippet = re.sub(r"\s+", " ", text[lo:hi]).strip()
    if lo > 0:
        snippet = "…" + snippet
    if hi < len(text):
        snippet += "…"
    return snippet[:110]


def analyze_bec(parsed: dict) -> dict:
    """Detect payment-fraud intent signals in one parsed email."""
    subject = parsed.get("subject") or ""
    body = parsed.get("body_text") or ""
    if not body and parsed.get("body_html"):
        body = re.sub(r"<[^>]+>", " ", parsed["body_html"])
    text = f"{subject}\n{body}"
    lowered = text.lower()

    from_domain = _domain_of(parsed.get("from"))
    reply_domain = _domain_of(parsed.get("reply_to"))
    signals: list[dict] = []

    for name, points, phrases in SIGNALS:
        for phrase in phrases:
            idx = lowered.find(phrase)
            if idx >= 0:
                signals.append(
                    {
                        "name": name,
                        "detail": f"BEC signal '{name}': message asks for or announces a payment-related change/action ('{phrase}').",
                        "evidence": _snippet(text, idx, idx + len(phrase)),
                        "points": points,
                    }
                )
                break  # one hit per signal is enough evidence

    # Executive impersonation needs both halves: an executive identity
    # claim AND a sender context that does not back it (free-mail
    # account, or replies diverted to a different domain). A CEO
    # writing from their own corporate domain does not fire this.
    title_hit = next((t for t in EXEC_TITLES if re.search(rf"\b{re.escape(t)}\b", lowered)), None)
    context_problem = None
    if from_domain in FREE_MAIL_DOMAINS:
        context_problem = f"sender uses free-mail domain {from_domain}"
    elif reply_domain and from_domain and reply_domain != from_domain:
        context_problem = f"replies go to {reply_domain}, not the sender's domain {from_domain}"
    if title_hit and context_problem:
        idx = lowered.find(title_hit)
        signals.append(
            {
                "name": "executive_impersonation_context",
                "detail": f"Message invokes an executive identity ('{title_hit}') while the {context_problem} — the classic CEO-fraud setup.",
                "evidence": _snippet(text, idx, idx + len(title_hit)),
                "points": 20,
            }
        )

    total = min(sum(s["points"] for s in signals), BEC_POINT_CAP)
    if total >= 40:
        risk = "high"
    elif total >= 15:
        risk = "elevated"
    else:
        risk = "low"

    return {
        "risk_level": risk,
        "bec_points": total,
        "signals": signals,
        "sender_domain": from_domain or None,
        "note": "Intent signals present in this single message only. A stateless analyser cannot verify sender history, thread continuity or whether a requested change matches a real vendor relationship.",
    }
