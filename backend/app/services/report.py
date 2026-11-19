"""Forensic PDF report generation (ReportLab).

Produces a self-contained analyst report from one analysis result:
verdict and score breakdown, email summary, header checks, URL
evidence, ML prediction, anomaly signals and the full reasons list.
Everything in the report comes from the analysis itself — no values
are added at report time.
"""

from __future__ import annotations

import datetime
import io
import re
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

VERDICT_LABELS = {
    "phishing": "PHISHING",
    "suspicious": "SUSPICIOUS",
    "likely_legitimate": "LIKELY LEGITIMATE",
}
VERDICT_COLORS = {
    "phishing": colors.HexColor("#b91c1c"),
    "suspicious": colors.HexColor("#b45309"),
    "likely_legitimate": colors.HexColor("#15803d"),
}


def _addr(field: dict | None) -> str:
    if not field:
        return "-"
    return field.get("raw") or field.get("email") or "-"


def defang(value: str) -> str:
    """Defang an indicator so it cannot be clicked or resolved by accident."""
    defanged = re.sub(r"http", "hxxp", value, flags=re.IGNORECASE)
    return defanged.replace(".", "[.]")


def collect_iocs(analysis: dict) -> list[dict]:
    """Collect the indicators of compromise, defanged, with their type.

    Sources: every analysed URL and its host, the originating IP, and
    the sender / reply-to addresses and domains. Values are
    deduplicated per (type, value) and sorted for a stable report.
    """
    parsed = analysis["parsed"]
    found: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str | None) -> None:
        if value:
            found.setdefault((kind, value), {"type": kind, "value": defang(value), "raw": value})

    for url in analysis["url_analysis"].get("urls", []):
        add("url", url.get("url"))
        add("domain", url.get("host"))
    add("ip", parsed.get("originating_ip"))
    for field_name in ("from", "reply_to", "return_path"):
        field = parsed.get(field_name) or {}
        add("email", field.get("email"))
        add("domain", field.get("domain"))
    return [found[key] for key in sorted(found)]


def attck_mapping(analysis: dict) -> list[dict]:
    """Map observed evidence to MITRE ATT&CK techniques — only what shows.

    T1566.002 (Spearphishing Link) when the message carries links;
    T1566.001 (Spearphishing Attachment) when it carries attachments.
    Nothing else is mapped: a technique is listed only when the
    corresponding evidence is present in this analysis.
    """
    mapping = []
    urls = analysis["url_analysis"].get("urls", [])
    if urls:
        qr_count = sum(1 for u in urls if u.get("source") == "qr")
        detail = f"{len(urls)} link(s) present in the message"
        if qr_count:
            detail += f", {qr_count} of them decoded from QR codes"
        suspicious = sum(1 for u in urls if u.get("suspicious"))
        detail += f"; {suspicious} flagged suspicious by lexical analysis."
        mapping.append(
            {
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "justification": detail,
            }
        )
    attachments = analysis["parsed"].get("attachments") or []
    if attachments:
        names = ", ".join(a.get("filename") or "(unnamed)" for a in attachments)
        mapping.append(
            {
                "id": "T1566.001",
                "name": "Phishing: Spearphishing Attachment",
                "justification": f"{len(attachments)} attachment(s) present: {names}. Attachment hashes are listed in the evidence section.",
            }
        )
    return mapping


def generate_report_pdf(analysis: dict) -> bytes:
    parsed = analysis["parsed"]
    verdict = analysis["verdict"]
    headers = analysis["header_forensics"]
    urls = analysis["url_analysis"]
    ml = analysis["ml_prediction"]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm)
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8.5, leading=11)
    story = []

    story.append(Paragraph("MailShield AI — Forensic Email Analysis Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", small))
    story.append(Spacer(1, 6))

    label = VERDICT_LABELS.get(verdict["verdict"], verdict["verdict"])
    verdict_table = Table(
        [[Paragraph(f"<b>Verdict: {label}</b>", styles["BodyText"]), Paragraph(f"<b>Risk score: {verdict['score']} / 100</b>", styles["BodyText"])]],
        colWidths=[85 * mm, 85 * mm],
    )
    verdict_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), VERDICT_COLORS.get(verdict["verdict"], colors.grey)),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(verdict_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Score breakdown (hybrid: rules .50 / ML .35 / anomaly .15)", styles["Heading2"]))
    comp = verdict["components"]
    rows = [["Component", "Score", "Weight used"]]
    for name in ("rules", "ml", "anomaly"):
        entry = comp.get(name, {})
        score_text = "-" if entry.get("score") is None else str(entry["score"])
        weight = verdict["weights_used"].get(name, entry.get("weight", "-"))
        rows.append([name.title(), score_text, str(weight)])
    if verdict.get("rule_floor_applied"):
        rows.append(["Safety floor", "Rule score >= 90 forced final score to at least 85", ""])
    story.append(Table(rows, colWidths=[40 * mm, 30 * mm, 100 * mm]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Email summary", styles["Heading2"]))
    summary = [
        ["Subject", parsed.get("subject") or "-"],
        ["From", _addr(parsed.get("from"))],
        ["Reply-To", _addr(parsed.get("reply_to"))],
        ["Return-Path", _addr(parsed.get("return_path"))],
        ["Date", parsed.get("date") or "-"],
        ["Originating IP", parsed.get("originating_ip") or "-"],
        ["Authentication", f"SPF={headers['auth']['spf']}  DKIM={headers['auth']['dkim']}  DMARC={headers['auth']['dmarc']}"],
        ["Spoofed sender suspected", "Yes" if headers.get("spoofed_sender_suspected") else "No"],
        ["ML prediction", f"{ml.get('label')} (probability {ml.get('phishing_probability')})" if ml.get("model_available") else "Model unavailable"],
    ]
    story.append(Table([[Paragraph(f"<b>{k}</b>", small), Paragraph(str(v), small)] for k, v in summary], colWidths=[40 * mm, 130 * mm]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Header forensics", styles["Heading2"]))
    rows = [[Paragraph("<b>Check</b>", small), Paragraph("<b>Status</b>", small), Paragraph("<b>Detail</b>", small)]]
    for check in headers.get("checks", []):
        rows.append([Paragraph(check["name"], small), Paragraph(check["status"], small), Paragraph(check["detail"], small)])
    story.append(Table(rows, colWidths=[35 * mm, 20 * mm, 115 * mm], repeatRows=1))
    story.append(Spacer(1, 6))

    alignment = headers.get("dmarc_alignment")
    if alignment:
        story.append(Paragraph("DMARC alignment", styles["Heading2"]))
        rows = [
            [Paragraph("<b>Mechanism</b>", small), Paragraph("<b>Result</b>", small), Paragraph("<b>Identity</b>", small), Paragraph("<b>Aligned with From</b>", small)],
            [Paragraph("SPF", small), Paragraph(alignment["spf"]["result"], small), Paragraph(_xml_escape(alignment["spf"]["identity_domain"] or "-"), small), Paragraph("Yes" if alignment["spf"]["aligned"] else "No", small)],
            [Paragraph("DKIM", small), Paragraph(alignment["dkim"]["result"], small), Paragraph(_xml_escape(", ".join(alignment["dkim"]["signing_domains"]) or "-"), small), Paragraph("Yes" if alignment["dkim"]["aligned"] else "No", small)],
            [Paragraph("DMARC (evaluated)", small), Paragraph(alignment["dmarc"]["evaluated_result"], small), Paragraph(f"From: {_xml_escape(alignment['from_domain'] or '-')}; receiver result: {alignment['dmarc']['receiver_result']}; policy: {alignment['dmarc']['policy'] or 'not in headers'}", small), Paragraph(alignment["dmarc"]["aligned_via"] or "-", small)],
        ]
        story.append(Table(rows, colWidths=[35 * mm, 25 * mm, 70 * mm, 40 * mm], repeatRows=1))
        story.append(Spacer(1, 6))

    story.append(Paragraph("URL analysis", styles["Heading2"]))
    if urls.get("urls"):
        rows = [[Paragraph("<b>URL</b>", small), Paragraph("<b>Points</b>", small), Paragraph("<b>Flags</b>", small)]]
        for url in urls["urls"]:
            flags = "; ".join(f["detail"] for f in url.get("flags", [])) or "No issues found"
            shown_url = url["url"] + (" (decoded from QR code)" if url.get("source") == "qr" else "")
            rows.append([Paragraph(_xml_escape(shown_url), small), Paragraph(str(url["points"]), small), Paragraph(_xml_escape(flags), small)])
        story.append(Table(rows, colWidths=[60 * mm, 15 * mm, 95 * mm], repeatRows=1))
    else:
        story.append(Paragraph("No URLs found in this email.", small))
    story.append(Spacer(1, 6))

    iocs = collect_iocs(analysis)
    story.append(Paragraph("Indicators of compromise (defanged)", styles["Heading2"]))
    if iocs:
        rows = [[Paragraph("<b>Type</b>", small), Paragraph("<b>Indicator</b>", small)]]
        for ioc in iocs:
            rows.append([Paragraph(ioc["type"], small), Paragraph(_xml_escape(ioc["value"]), small)])
        story.append(Table(rows, colWidths=[30 * mm, 140 * mm], repeatRows=1))
    else:
        story.append(Paragraph("No indicators were extracted from this email.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("MITRE ATT&CK mapping", styles["Heading2"]))
    mapping = attck_mapping(analysis)
    if mapping:
        for entry in mapping:
            story.append(Paragraph(f"<b>{entry['id']} — {_xml_escape(entry['name'])}</b>: {_xml_escape(entry['justification'])}", small))
    else:
        story.append(Paragraph("No ATT&CK techniques are mapped: the message carries no links and no attachments, so no T1566 sub-technique is justified by the evidence.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Reasons behind the verdict", styles["Heading2"]))
    if verdict.get("reasons"):
        for reason in verdict["reasons"]:
            story.append(Paragraph(f"[{reason['source']}] {reason['detail']}", small))
    else:
        story.append(Paragraph("No risk signals fired. Headers authenticate cleanly, links are clean, and no social-engineering language was detected.", small))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Evidence and chain of custody", styles["Heading2"]))
    evidence = analysis.get("evidence") or {}
    custody = [
        ["Email SHA-256", evidence.get("email_sha256") or "not recorded (report generated outside the analysis endpoints)"],
        ["Email size (bytes)", str(evidence.get("email_size_bytes") or "-")],
        ["Analysed at (UTC)", evidence.get("analysed_at_utc") or "-"],
        ["Tool", f"{evidence.get('tool') or 'MailShield AI'} {evidence.get('tool_version') or ''}".strip()],
        ["Handling", "Hash computed at analysis time over the bytes exactly as received. MailShield AI is stateless: no copy of the email is retained after the request, so this hash is the reference for verifying any separately preserved copy."],
    ]
    story.append(Table([[Paragraph(f"<b>{k}</b>", small), Paragraph(_xml_escape(str(v)), small)] for k, v in custody], colWidths=[40 * mm, 130 * mm]))
    attachments = parsed.get("attachments") or []
    if attachments:
        story.append(Spacer(1, 4))
        rows = [[Paragraph("<b>Attachment</b>", small), Paragraph("<b>Size (bytes)</b>", small), Paragraph("<b>SHA-256</b>", small)]]
        for att in attachments:
            rows.append([Paragraph(_xml_escape(att.get("filename") or "(unnamed)"), small), Paragraph(str(att.get("size_bytes") or "-"), small), Paragraph(_xml_escape(att.get("sha256") or "-"), small)])
        story.append(Table(rows, colWidths=[45 * mm, 25 * mm, 100 * mm], repeatRows=1))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Generated by MailShield AI. Scores are computed from the email's headers, links, message text and behavioural signals at analysis time. What this report did not do: no link was visited, no attachment was executed or detonated, and no external threat-intelligence lookup was performed.", small))

    doc.build(story)
    return buffer.getvalue()
