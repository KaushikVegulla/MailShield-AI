"""Optional LLM explanation of an analysis — narrator, never scorer.

The deterministic pipeline (rules + ML + anomaly) produces the
verdict. This service optionally asks Google Gemini to *explain that
finished analysis* in plain language for a non-expert reader. It has
no path into scoring: nothing in the analysis pipeline imports this
module, and the explanation is generated after the verdict exists.

Privacy and safety properties, by construction:

- The prompt is built **only from the structured analysis result**
  (verdict, reasons, check outcomes) — the raw email, its body and
  its headers are never sent to the LLM, so there is no email content
  for a prompt-injection attack to work on and no user mail leaves
  the machine beyond the findings themselves.
- The model is instructed to cite the specific evidence given, to
  invent nothing, and to never restate or change the score. The
  response returns the deterministic score alongside the prose as
  ``score_unchanged`` so a caller can verify it was not touched.

Configuration is environment-only: ``GEMINI_API_KEY`` (required) and
``GEMINI_MODEL`` (optional, default below). Without the key the
service reports ``available: False`` — that is the expected state on
deployments where the operator has not enabled it.
"""

from __future__ import annotations

import json
import os
import urllib.request

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_MODEL = "gemini-3.5-flash"
TIMEOUT_SECONDS = 10.0


def _build_prompt(analysis: dict) -> str:
    verdict = analysis.get("verdict") or {}
    lines = [
        "You are explaining an email security analysis to a non-expert reader.",
        "Rules you must follow:",
        "- Explain in plain, calm language, in at most 180 words.",
        "- Base every statement ONLY on the evidence listed below. Do not invent facts, senders, links or events that are not listed.",
        "- Do not state, restate, or suggest any risk score or percentage of your own — the deterministic system already scored this email; your job is only to explain its reasons in words.",
        "- End with one practical recommendation for the reader.",
        "",
        f"Deterministic verdict (do not quote the number): {verdict.get('verdict')}",
        "",
        "Evidence (strongest first):",
    ]
    reasons = verdict.get("reasons") or []
    for reason in reasons[:8]:
        lines.append(f"- [{reason.get('source')}] {reason.get('detail')}")
    if not reasons:
        lines.append("- No rule, feed, ML or anomaly signal fired on this message.")

    headers = analysis.get("header_forensics") or {}
    failed = [c.get("name") for c in headers.get("checks", []) if c.get("status") == "fail"]
    if failed:
        lines.append(f"Authentication checks that failed: {', '.join(failed)}")
    feed = analysis.get("feed_analysis") or {}
    if feed.get("available"):
        lines.append(f"Threat-feed status: loaded, {feed.get('total_entries')} known-bad URLs indexed.")
    bec = analysis.get("bec_analysis") or {}
    if bec.get("risk_level") and bec.get("risk_level") != "low":
        lines.append(f"Payment-fraud (BEC) intent risk: {bec['risk_level']}.")
    attachments = analysis.get("attachment_analysis") or {}
    if attachments.get("flagged_count"):
        lines.append(f"Attachments flagged by triage: {attachments['flagged_count']} of {attachments.get('attachment_count')}.")
    qr = analysis.get("qr_analysis") or {}
    if qr.get("urls"):
        lines.append(f"QR codes in the message decoded to: {', '.join(qr['urls'])}")
    return "\n".join(lines)


def _call_gemini(prompt: str, api_key: str, model: str, timeout: float = TIMEOUT_SECONDS) -> str:
    """One generateContent call. Raises on any failure."""
    url = f"{API_BASE}/{model}:generateContent"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("x-goog-api-key", api_key)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    parts = data["candidates"][0]["content"]["parts"]
    return "".join(part.get("text", "") for part in parts).strip()


def explain_analysis(analysis: dict) -> dict:
    """Explain a finished analysis, or report why that is unavailable."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {"available": False, "reason": "GEMINI_API_KEY not configured"}
    model = os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL
    verdict = analysis.get("verdict") or {}
    try:
        text = _call_gemini(_build_prompt(analysis), api_key, model)
    except Exception as exc:  # fail-open: explanation is optional garnish
        return {"available": False, "reason": f"Gemini request failed: {type(exc).__name__}", "model": model}
    if not text:
        return {"available": False, "reason": "Gemini returned an empty explanation", "model": model}
    return {
        "available": True,
        "explanation": text,
        "model": model,
        "score_unchanged": verdict.get("score"),
        "verdict_unchanged": verdict.get("verdict"),
    }
