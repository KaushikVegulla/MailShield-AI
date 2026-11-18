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

    story.append(Paragraph("URL analysis", styles["Heading2"]))
    if urls.get("urls"):
        rows = [[Paragraph("<b>URL</b>", small), Paragraph("<b>Points</b>", small), Paragraph("<b>Flags</b>", small)]]
        for url in urls["urls"]:
            flags = "; ".join(f["detail"] for f in url.get("flags", [])) or "No issues found"
            rows.append([Paragraph(url["url"], small), Paragraph(str(url["points"]), small), Paragraph(flags, small)])
        story.append(Table(rows, colWidths=[60 * mm, 15 * mm, 95 * mm], repeatRows=1))
    else:
        story.append(Paragraph("No URLs found in this email.", small))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Reasons behind the verdict", styles["Heading2"]))
    if verdict.get("reasons"):
        for reason in verdict["reasons"]:
            story.append(Paragraph(f"[{reason['source']}] {reason['detail']}", small))
    else:
        story.append(Paragraph("No risk signals fired. Headers authenticate cleanly, links are clean, and no social-engineering language was detected.", small))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Generated by MailShield AI. Scores are computed from the email's headers, links, message text and behavioural signals at analysis time.", small))

    doc.build(story)
    return buffer.getvalue()
