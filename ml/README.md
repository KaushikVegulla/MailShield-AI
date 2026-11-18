# ML pipeline

Classifier for phishing email text (subject + body).

## Dataset — real public corpora, no account needed

Built by `download_data.py` + `dataset.py` from two classic public sources:

- **Phishing:** Nazario Phishing Corpus — hand-collected real phishing emails, mbox files at https://monkey.org/~jose/phishing/
- **Legitimate:** SpamAssassin public corpus — `easy_ham` and `hard_ham` archives at https://spamassassin.apache.org/old/publiccorpus/

The Kaggle "Phishing Email Dataset" (which itself combines Nazario, Enron, CEAS, Ling, Nigerian Fraud and SpamAssassin) was the original plan, but it needs a Kaggle account to download; these direct sources need no credentials and contain the same underlying Nazario/SpamAssassin material.

First run (18 Nov 2026): 5,778 usable emails after cleaning and deduplication — 3,059 phishing, 2,719 legitimate (1,459 duplicates and 86 empty messages skipped). Only subject + body text is used, no headers.

## Approach

- TF-IDF features: word n-grams (1,2), max 15,000 features, sublinear scaling
- Candidates: Logistic Regression (baseline) and XGBoost, same stratified 80/20 split (seed 42)
- The model with the higher test F1 (ties go to the simpler Logistic Regression) is saved to `models/phishing_pipeline.joblib` — a binary artefact that is **not** committed to GitHub
- `evaluate.py` writes the real measured metrics to `metrics.json`

## Real measured results (18 Nov 2026)

Held-out test split, 1,156 emails:

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression | 0.9939 | 0.9951 | 0.9935 | 0.9943 |
| XGBoost | 0.9939 | 0.9935 | 0.9951 | 0.9943 |

Selected model: **Logistic Regression** (tie on F1, simpler model preferred).

## Honest limitations

- These are **in-domain** metrics: both corpora are from 2002–2007, and held-out mail from the same corpora is easier than modern mail.
- Checked against this repo's modern demo samples, the model scores the two phishing samples 0.997 and 0.937 — but it also scores the two short modern legitimate samples (a college exam notice and a GitHub digest) at 0.79 and 0.73, i.e. it would call them phishing on text alone. Short modern legitimate mail is out-of-distribution for 2000s corpora.
- That is exactly why MailShield's final verdict is **hybrid**: headers and URL evidence carry most of the weight, and the ML score is one signal of three — not the decision by itself.

## Reproduce

```bash
cd ml
pip install scikit-learn==1.6.0 xgboost==3.0.2 joblib
python download_data.py
python train.py      # saves models/phishing_pipeline.joblib
python evaluate.py   # writes metrics.json
```
