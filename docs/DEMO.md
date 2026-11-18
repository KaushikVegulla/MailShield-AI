# Demo

Goal: a visitor pastes a sample phishing email and sees a red verdict with evidence in under 10 seconds.

## Script

1. Open the dashboard, load the PayPal sample (one click in the dashboard, or paste `samples/phishing_paypal.eml`).
2. Expected: **95 / 100, PHISHING** — SPF fail, DMARC fail, IP-based link displayed as paypal.com, ML probability ~100%, urgency + credential-request language, all listed as reasons.
3. Load the bank KYC sample.
4. Expected: **83 / 100, PHISHING** — SPF softfail, Reply-To mismatch, bit.ly shortener and a punycode look-alike link.
5. Load `samples/legit_college.eml`.
6. Expected: **28 / 100, LIKELY LEGITIMATE** — SPF/DKIM/DMARC all pass and links are clean. Point out that the ML text score alone is 79 here: the hybrid system is what lands this correctly, which is the design story.
7. Download the forensic PDF for the PayPal sample and show the verdict, score breakdown and reasons sections.

## Measured timing (18 Nov 2026, local machine)

Against a running backend (uvicorn), full `/analyze/email` calls:

- First call (includes one-time ML model load): **1,470 ms**
- Subsequent calls: **5–8 ms**
- Forensic PDF generation: **~20 ms** warm (4,983 bytes for the PayPal sample)

All well under the 10-second demo goal. Hosted timings on Render's free tier will be higher on a cold start; that is a hosting property, not an analysis cost.
