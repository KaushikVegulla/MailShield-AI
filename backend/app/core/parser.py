"""Email parsing: raw text and .eml files into structured fields.

Uses only the Python standard library (`email` package) so parsing works
the same locally, in tests, and on the hosted backend.
"""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr

IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _domain_of(address: str | None) -> str | None:
    if not address:
        return None
    _, addr = parseaddr(address)
    addr = (addr or address).strip().lower()
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip(" <>") or None


def _address_field(value: str | None) -> dict | None:
    if not value:
        return None
    name, addr = parseaddr(value)
    return {
        "raw": value,
        "name": name or None,
        "email": addr.lower() if addr else None,
        "domain": _domain_of(value),
    }


def _decode_part(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def parse_email(raw: str | bytes) -> dict:
    """Parse a raw email (paste or .eml contents) into a structured dict."""
    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        if "\n\n" not in raw and ":" not in raw.split("\n", 1)[0]:
            return {
                "subject": None,
                "from": None,
                "to": None,
                "reply_to": None,
                "return_path": None,
                "date": None,
                "message_id": None,
                "authentication_results": None,
                "received": [],
                "originating_ip": None,
                "body_text": raw,
                "body_html": None,
                "attachments": [],
            }
        msg = Parser(policy=policy.default).parsestr(raw)

    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[dict] = []

    parts = list(msg.walk()) if msg.is_multipart() else [msg]

    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        if disposition == "attachment" or (part.get_filename() and content_type not in ("text/plain", "text/html")):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                {
                    "filename": part.get_filename(),
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                }
            )
        elif content_type == "text/plain":
            text = _decode_part(part)
            if text:
                body_text_parts.append(text)
        elif content_type == "text/html":
            html = _decode_part(part)
            if html:
                body_html_parts.append(html)

    received_raw = [str(v) for v in (msg.get_all("Received") or [])]
    received = []
    for entry in received_raw:
        ips = IP_RE.findall(entry)
        received.append({"raw": " ".join(entry.split()), "ips": ips})
    originating_ip = None
    for entry in reversed(received):
        if entry["ips"]:
            originating_ip = entry["ips"][0]
            break

    auth = msg.get("Authentication-Results")
    return {
        "subject": str(msg.get("Subject")) if msg.get("Subject") else None,
        "from": _address_field(str(msg.get("From"))) if msg.get("From") else None,
        "to": _address_field(str(msg.get("To"))) if msg.get("To") else None,
        "reply_to": _address_field(str(msg.get("Reply-To"))) if msg.get("Reply-To") else None,
        "return_path": _address_field(str(msg.get("Return-Path"))) if msg.get("Return-Path") else None,
        "date": str(msg.get("Date")) if msg.get("Date") else None,
        "message_id": str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
        "authentication_results": str(auth) if auth else None,
        "received": received,
        "originating_ip": originating_ip,
        "body_text": "\n".join(body_text_parts) or None,
        "body_html": "\n".join(body_html_parts) or None,
        "attachments": attachments,
    }
