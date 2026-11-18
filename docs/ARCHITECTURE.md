# Architecture

MailShield AI follows the same proven split as ShieldNet: a FastAPI backend that does all analysis, and a React frontend that only presents results.

## Pipeline

1. **Parse** — raw text or `.eml` upload is parsed with Python's `email` library into headers, body, links and attachments metadata.
2. **Header forensics** — `Authentication-Results` is read for SPF / DKIM / DMARC verdicts; From, Reply-To, Return-Path and the Received chain are compared for spoofing signals.
3. **URL analysis** — every link is extracted from HTML and plain-text bodies and checked for IP hosts, shorteners, punycode, look-alike domains and display-text mismatch.
4. **ML classification** — subject + body text is vectorised with TF-IDF and scored by a classifier trained on a real public phishing dataset (`ml/`).
5. **Hybrid scoring** — rules (0.50), ML (0.35) and anomaly signals (0.15) are combined into a single 0-100 risk score. Every contributing signal is kept as a human-readable reason.
6. **Report** — the analysis is shown in the dashboard and can be exported as a forensic PDF.

## Verdict bands

- 0-39: Likely legitimate
- 40-74: Suspicious — review evidence
- 75-100: Phishing / malicious — do not interact

These bands mirror ShieldNet's monitor / block thresholds concept, adapted for email triage.
