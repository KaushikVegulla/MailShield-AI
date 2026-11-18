# Demo

Goal: a visitor pastes a sample phishing email and sees a red verdict with evidence in under 10 seconds.

## Script

1. Open the dashboard and load `samples/phishing_paypal.eml`.
2. Expected: high-risk verdict — SPF fail, From domain mismatch, IP-based / look-alike URL flagged, ML classifier scores it as phishing, reasons listed.
3. Load `samples/legit_college.eml`.
4. Expected: low-risk verdict — SPF/DKIM/DMARC pass, no suspicious URLs.
5. Download the forensic PDF for the phishing sample and show the evidence section.

## Status

Demo samples are included from the scaffold. End-to-end timing is measured once the analysis pipeline is wired up, and the real measured result will be recorded here — no placeholder figures.
