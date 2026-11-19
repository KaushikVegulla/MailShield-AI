"""Attachment triage: dangerous files, archives, macros, PDF scripts.

Static, stdlib-only inspection — nothing is executed or detonated.
For each attachment the module reports findings with points:

- **Dangerous extension** (exe, scr, ps1, lnk, iso, msi, jar, ...):
  40 points. This is the same filename-level risk the anomaly channel
  used to score; scoring now happens here, once, and the anomaly
  module is told not to score attachments again (see api/analyze.py),
  so the evidence is never double-counted.
- **Double extension** (``invoice.pdf.exe``): +15 — a document costume
  over an executable.
- **Archive contents**: ZIP files (and RAR files by extension only —
  stdlib cannot read RAR) are listed; a dangerous member inside an
  archive scores 30, because the archive is just the wrapper.
- **Office macros**: macro-enabled file types (docm/xlsm/pptm) score
  20 by type; an Office zip actually containing ``vbaProject.bin``
  scores 30 — macros are present, not hypothetical. Legacy OLE Office
  files (.doc/.xls/.ppt with the OLE magic) get a 10-point macro-risk
  note: the format can carry macros, presence is not proven.
- **PDF active content**: ``/JavaScript``, ``/Launch`` or embedded
  files score 25; an ``/OpenAction`` (runs on open) scores 15.

Per-attachment points are capped at 60 and the channel total at 100.
Payload bytes are re-read from the raw message (the parser keeps only
metadata); when bytes are unavailable, filename-level findings still
apply and content checks report themselves as not performed.
"""

from __future__ import annotations

import io
import zipfile
from email import policy
from email.parser import BytesParser, Parser

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf",
    "wsh", "hta", "lnk", "iso", "img", "msi", "dll", "jar", "cpl", "msc",
    "reg", "gadget", "application", "xll",
}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf"}
MACRO_ENABLED_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
OFFICE_ZIP_EXTENSIONS = {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
LEGACY_OFFICE_EXTENSIONS = {"doc", "xls", "ppt", "dot", "xlt", "pot"}
ARCHIVE_EXTENSIONS = {"zip", "jar", "rar", "7z"}

POINTS = {
    "dangerous_extension": 40,
    "double_extension": 15,
    "archive_dangerous_member": 30,
    "macro_detected": 30,
    "macro_enabled_type": 20,
    "pdf_active_content": 25,
    "pdf_open_action": 15,
    "legacy_macro_risk": 10,
}
ATTACHMENT_CAP = 60

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _finding(name: str, status: str, detail: str, points: int) -> dict:
    return {"name": name, "status": status, "detail": detail, "points": points}


def _payloads_from_raw(raw: str | bytes) -> dict[str, bytes]:
    """Map attachment filename -> payload bytes, re-parsed from raw."""
    payloads: dict[str, bytes] = {}
    try:
        if isinstance(raw, bytes):
            msg = BytesParser(policy=policy.default).parsebytes(raw)
        else:
            msg = Parser(policy=policy.default).parsestr(raw)
    except Exception:
        return payloads
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        if filename and payload:
            payloads.setdefault(filename, payload)
    return payloads


def _zip_members(data: bytes) -> list[str] | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return archive.namelist()
    except Exception:
        return None


def triage_attachment(filename: str, data: bytes | None, content_type: str | None = None) -> dict:
    """Triage one attachment from its name and (if available) bytes."""
    name = filename or "(unnamed)"
    lower = name.lower()
    ext = _ext(lower)
    findings: list[dict] = []
    archive_members: list[str] = []

    if ext in DANGEROUS_EXTENSIONS:
        findings.append(_finding("dangerous_extension", "fail", f"'{name}' has a dangerous extension (.{ext}) — executable or script attachments are the classic malware delivery route.", POINTS["dangerous_extension"]))
        parts = lower.split(".")
        if len(parts) >= 3 and parts[-2] in DOCUMENT_EXTENSIONS:
            findings.append(_finding("double_extension", "fail", f"'{name}' uses a double extension: a .{parts[-2]} costume over a .{ext} executable, so it looks like a document in file listings.", POINTS["double_extension"]))

    if ext in MACRO_ENABLED_EXTENSIONS:
        findings.append(_finding("macro_enabled_type", "warn", f"'{name}' is a macro-enabled Office file type (.{ext}) — this format exists to carry VBA macros.", POINTS["macro_enabled_type"]))

    if data is not None and ext in OFFICE_ZIP_EXTENSIONS:
        members = _zip_members(data)
        if members is not None:
            archive_members = members[:50]
            if any(m.lower().endswith("vbaproject.bin") for m in members):
                findings.append(_finding("macro_detected", "fail", f"'{name}' actually contains a VBA macro project (vbaProject.bin) — macros are present, not just possible.", POINTS["macro_detected"]))

    if data is not None and ext in LEGACY_OFFICE_EXTENSIONS and data.startswith(OLE_MAGIC):
        findings.append(_finding("legacy_macro_risk", "warn", f"'{name}' is a legacy OLE Office file (.{ext}) — the format can embed macros; static triage cannot prove whether it does.", POINTS["legacy_macro_risk"]))

    if ext in ARCHIVE_EXTENSIONS and data is not None:
        if ext == "zip" or ext == "jar":
            members = _zip_members(data)
            if members is not None:
                archive_members = members[:50]
                dangerous = [m for m in members if _ext(m.lower()) in DANGEROUS_EXTENSIONS]
                if dangerous:
                    findings.append(_finding("archive_dangerous_member", "fail", f"Archive '{name}' contains dangerous file(s): {', '.join(dangerous[:5])} — the archive is only a wrapper; the payload inside is executable.", POINTS["archive_dangerous_member"]))
            else:
                findings.append(_finding("archive_unreadable", "warn", f"Archive '{name}' could not be opened for inspection (corrupt or unsupported compression).", 0))
        else:
            findings.append(_finding("archive_not_inspected", "warn", f"Archive '{name}' (.{ext}) cannot be listed with the standard library — its contents were not inspected.", 0))

    if data is not None and (ext == "pdf" or (content_type or "").lower() == "application/pdf"):
        if b"/JavaScript" in data or b"/Launch" in data or b"/EmbeddedFile" in data:
            findings.append(_finding("pdf_active_content", "fail", f"PDF '{name}' carries active content (JavaScript, a launch action, or an embedded file) — PDFs used as malware droppers hide payloads this way.", POINTS["pdf_active_content"]))
        elif b"/OpenAction" in data or b"/AA" in data:
            findings.append(_finding("pdf_open_action", "warn", f"PDF '{name}' defines an action that runs automatically when the file is opened (/OpenAction).", POINTS["pdf_open_action"]))

    points = min(sum(f["points"] for f in findings), ATTACHMENT_CAP)
    return {
        "filename": filename,
        "content_type": content_type,
        "inspected": data is not None,
        "archive_members": archive_members,
        "findings": findings,
        "points": points,
    }


def analyze_attachments(raw: str | bytes, parsed: dict) -> dict:
    """Triage every attachment of a parsed email.

    Returns per-attachment findings and the channel total that the
    hybrid scorer folds into the anomaly weight (see scoring.py).
    """
    payloads = _payloads_from_raw(raw) if raw else {}
    results = []
    for attachment in parsed.get("attachments") or []:
        filename = attachment.get("filename")
        data = payloads.get(filename) if filename else None
        entry = triage_attachment(filename or "(unnamed)", data, attachment.get("content_type"))
        entry["size_bytes"] = attachment.get("size_bytes")
        entry["sha256"] = attachment.get("sha256")
        results.append(entry)
    return {
        "attachments": results,
        "attachment_count": len(results),
        "flagged_count": sum(1 for r in results if r["points"] > 0),
        "attachment_points": min(sum(r["points"] for r in results), 100),
        "note": None if results else "The message carries no attachments.",
    }
