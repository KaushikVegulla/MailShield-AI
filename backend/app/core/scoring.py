"""Hybrid risk scoring: rules .50 / ML .35 / anomaly .15, with reasons.

Same hybrid concept as ShieldNet, adapted for email:

- **Rules (0.50)** combine the two deterministic evidence channels —
  header forensics and URL analysis. The stronger channel counts in
  full and the weaker adds a quarter of its points, so independent
  corroborating evidence compounds instead of averaging away, while a
  single channel alone cannot reach the maximum by itself.
- **ML (0.35)** is the trained classifier's phishing probability x 100.
- **Anomaly (0.15)** is social-engineering language + attachment risk.

If the ML model is unavailable, the remaining weights are renormalised
so a missing model never silently drags the score down. A safety floor
mirrors ShieldNet: a rule score of 90+ (both evidence channels strongly
flagging) forces the final score to at least 85.

Verdict bands: 0-39 likely legitimate, 40-74 suspicious, 75-100 phishing.
Every component and every individual reason is returned, so the verdict
is fully explainable in the dashboard and the forensic report.
"""

from __future__ import annotations

WEIGHTS = {"rules": 0.50, "ml": 0.35, "anomaly": 0.15}


def _verdict(score: int) -> str:
    if score >= 75:
        return "phishing"
    if score >= 40:
        return "suspicious"
    return "likely_legitimate"


def combine_scores(header_points: int, url_points: int, ml_points: int | None, anomaly_points: int) -> dict:
    rule_score = min(100.0, max(header_points, url_points) + 0.25 * min(header_points, url_points))

    components = {
        "rules": {"score": round(rule_score, 1), "weight": WEIGHTS["rules"], "header_points": header_points, "url_points": url_points},
        "anomaly": {"score": anomaly_points, "weight": WEIGHTS["anomaly"]},
    }
    total_weight = WEIGHTS["rules"] + WEIGHTS["anomaly"]
    weighted = rule_score * WEIGHTS["rules"] + anomaly_points * WEIGHTS["anomaly"]

    if ml_points is not None:
        components["ml"] = {"score": ml_points, "weight": WEIGHTS["ml"]}
        total_weight += WEIGHTS["ml"]
        weighted += ml_points * WEIGHTS["ml"]
    else:
        components["ml"] = {"score": None, "weight": WEIGHTS["ml"], "note": "model unavailable — weights renormalised over rules and anomaly"}

    score = int(round(weighted / total_weight))

    floor_applied = False
    if rule_score >= 90 and score < 85:
        score = 85
        floor_applied = True

    return {
        "score": score,
        "verdict": _verdict(score),
        "components": components,
        "weights_used": {k: round(v / total_weight, 4) for k, v in WEIGHTS.items() if k != "ml" or ml_points is not None},
        "rule_floor_applied": floor_applied,
    }


def build_reasons(header_forensics: dict, url_analysis: dict, ml_prediction: dict, anomaly: dict, attachment_analysis: dict | None = None, bec_analysis: dict | None = None) -> list[dict]:
    """Flatten every signal that fired into one explainable list."""
    reasons: list[dict] = []

    for check in header_forensics.get("checks", []):
        if check.get("points"):
            reasons.append({"source": "headers", "detail": check["detail"], "points": check["points"]})

    for url in url_analysis.get("urls", []):
        for flag in url.get("flags", []):
            if flag.get("points"):
                if flag.get("source") == "feed":
                    reasons.append({"source": "feed", "detail": f"{url['url']} — {flag['detail']}", "points": flag["points"]})
                elif flag.get("source") == "redirect":
                    reasons.append({"source": "redirect", "detail": f"{url['url']} — {flag['detail']}", "points": flag["points"]})
                elif url.get("source") == "qr":
                    detail = f"QR code decoded link {url['url']} — {flag['detail']}"
                    reasons.append({"source": "qr", "detail": detail, "points": flag["points"]})
                else:
                    reasons.append({"source": "url", "detail": f"{url['url']} — {flag['detail']}", "points": flag["points"]})

    if ml_prediction.get("model_available") and ml_prediction.get("phishing_probability") is not None:
        prob = ml_prediction["phishing_probability"]
        reasons.append(
            {
                "source": "ml",
                "detail": f"ML classifier ({ml_prediction.get('model_name')}) gives a {prob:.0%} phishing probability for the message text.",
                "points": ml_prediction.get("ml_points"),
            }
        )

    for signal in anomaly.get("signals", []):
        reasons.append({"source": "anomaly", "detail": signal["detail"], "points": signal["points"]})

    for attachment in (attachment_analysis or {}).get("attachments", []):
        for finding in attachment.get("findings", []):
            if finding.get("points"):
                reasons.append({"source": "attachment", "detail": finding["detail"], "points": finding["points"]})

    for signal in (bec_analysis or {}).get("signals", []):
        if signal.get("points"):
            reasons.append({"source": "bec", "detail": signal["detail"], "points": signal["points"]})

    reasons.sort(key=lambda r: (r["points"] is None, -(r["points"] or 0)))
    return reasons


def score_email(parsed: dict, header_forensics: dict, url_analysis: dict, ml_prediction: dict, anomaly: dict, attachment_analysis: dict | None = None, bec_analysis: dict | None = None) -> dict:
    # Attachment triage points ride the anomaly weight (0.15): both are
    # behavioural/content evidence rather than header or link rules,
    # and the anomaly module no longer scores attachments itself when
    # triage ran, so nothing is counted twice. BEC intent points ride
    # the same weight for the same reason — payment-fraud intent is
    # content evidence, and its module caps its own contribution.
    anomaly_points = anomaly.get("anomaly_points", 0)
    if attachment_analysis is not None:
        anomaly_points = min(100, anomaly_points + attachment_analysis.get("attachment_points", 0))
    if bec_analysis is not None:
        anomaly_points = min(100, anomaly_points + bec_analysis.get("bec_points", 0))
    result = combine_scores(
        header_points=header_forensics.get("rule_points", 0),
        url_points=url_analysis.get("url_points", 0),
        ml_points=ml_prediction.get("ml_points"),
        anomaly_points=anomaly_points,
    )
    if attachment_analysis is not None:
        result["components"]["anomaly"]["attachment_points"] = attachment_analysis.get("attachment_points", 0)
    if bec_analysis is not None:
        result["components"]["anomaly"]["bec_points"] = bec_analysis.get("bec_points", 0)
    result["reasons"] = build_reasons(header_forensics, url_analysis, ml_prediction, anomaly, attachment_analysis, bec_analysis)
    result["anomaly_signals"] = anomaly.get("signals", [])
    return result
