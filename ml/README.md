# ML pipeline

Classifier for phishing email text (subject + body).

## Dataset — real public corpora, no account needed

Built by `download_data.py` + `dataset.py` from two classic public sources:

- **Phishing:** Nazario Phishing Corpus — hand-collected real phishing emails, mbox files at https://monkey.org/~jose/phishing/
- **Legitimate:** SpamAssassin public corpus — `easy_ham` and `hard_ham` archives at https://spamassassin.apache.org/old/publiccorpus/

The Kaggle "Phishing Email Dataset" (which itself combines Nazario, Enron, CEAS, Ling, Nigerian Fraud and SpamAssassin) was the original plan, but it needs a Kaggle account to download; these direct sources need no credentials and contain the same underlying Nazario/SpamAssassin material.

First run (18 Nov 2026): 5,778 usable emails after cleaning and deduplication — 3,059 phishing, 2,719 legitimate (1,459 duplicates and 86 empty messages skipped). Only subject + body text is used as model features, no headers.

## Approach

- TF-IDF features: word n-grams (1,2), max 15,000 features, sublinear scaling
- Candidates: Logistic Regression (baseline) and XGBoost, same splits (seed 42)
- The model with the higher random-split test F1 (ties go to the simpler Logistic Regression) is saved to `models/phishing_pipeline.joblib` — a binary artefact that is **not** committed to GitHub
- `evaluate.py` writes the real measured metrics to `metrics.json`
- `evaluate_heldout.py` runs the saved model on a folder of never-trained `.eml` files (see below)

## Evaluation: three splits, not one

Deduplication is by **full body hash** (SHA-256 of the cleaned subject + body), applied before any split. Current run: **6,048 emails** — 3,324 phishing, 2,724 legitimate; 1,189 exact duplicates removed, 86 empty skipped. (The first run deduplicated on a 400-character prefix, which removes more near-duplicates; its numbers are preserved in `metrics.json` under `previous_published_run`.)

A single random split flatters a model: near-duplicates, the same campaign, and the same senders can appear in both train and test. So `evaluate.py` now reports three splits:

| Split | What it asks | Logistic Regression F1 | XGBoost F1 |
|---|---|---|---|
| Random stratified 80/20 | The original evaluation, kept for comparability | 0.9932 (FPR 0.0055) | 0.9887 |
| Temporal (oldest 80% train, newest 20% test, by Date header) | Does a model trained on older mail still work on newer mail? | 0.9613 | 0.9706 |
| Group by sender domain (no sender on both sides) | Does it generalise to senders it has never seen? | 0.9955 (FPR 0.0118) | 0.9909 |

**Read the temporal row with its warning** (also in `metrics.json`): the temporal test slice holds 1,208 phishing messages but only **1 legitimate** one, because the SpamAssassin ham is from 2002–2003 while the Nazario phishing corpus extends years later. Its precision and false-positive rate therefore rest on a single legitimate message and must not be quoted without that context. The split is kept — and labelled — because that imbalance is itself a finding about these corpora. A handful of messages also carry implausible Date headers (the parsed range runs 1970–2038 — mis-set clocks and forged dates are common in these corpora); they sort to the edges of the split and are part of the reported date range in `metrics.json`.

## Held-out harness for data the corpora cannot provide

No public ham corpus is modern, so the honest way to measure performance on modern mail is a folder of messages the model never trained on:

```bash
python evaluate_heldout.py path/to/folder --label legitimate   # or --label phishing
python evaluate_heldout.py ../samples --label from-filename    # phishing_*.eml / legit_*.eml naming
```

Every file's body hash is checked against the training corpora (when they are downloaded), so a "held-out" file that was actually trained on is flagged. An illustrative run on this repo's own four samples is saved in `heldout_samples_results.json`: none of the four is in the training corpora; the retrained model scores the PayPal sample **0.9975** and the bank sample **0.9411** phishing — and the two modern legitimate samples **0.7606** and **0.6949**, i.e. phishing on text alone. Four files illustrate behaviour; they are not a benchmark. A consented set of a few hundred modern legitimate messages (OTPs, receipts, GitHub/Google notifications, newsletters) is the dataset that would turn this into a real measurement.

## Real measured results (first run, 18 Nov 2026)

Held-out random test split, 1,156 emails:

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression | 0.9939 | 0.9951 | 0.9935 | 0.9943 |
| XGBoost | 0.9939 | 0.9935 | 0.9951 | 0.9943 |

Selected model: **Logistic Regression** (tie on F1, simpler model preferred). The current run selects Logistic Regression too (random-split F1 0.9932 vs XGBoost 0.9887).

## Honest limitations

- These are **in-domain** metrics: both corpora are from 2002–2007, and held-out mail from the same corpora is easier than modern mail. The three-split evaluation above shows how much the answer depends on how you split.
- Checked against this repo's modern demo samples, the model scores the two phishing samples 0.9975 and 0.9411 — but it also scores the two short modern legitimate samples (a college exam notice and a GitHub digest) at 0.7606 and 0.6949, i.e. it would call them phishing on text alone. Short modern legitimate mail is out-of-distribution for 2000s corpora.
- That is exactly why MailShield's final verdict is **hybrid**: headers and URL evidence carry most of the weight, and the ML score is one signal of three — not the decision by itself.

## Reproduce

```bash
cd ml
pip install scikit-learn==1.6.0 xgboost==3.0.2 joblib
python download_data.py
python train.py      # saves models/phishing_pipeline.joblib
python evaluate.py   # writes metrics.json (three splits)
python evaluate_heldout.py ../samples --label from-filename   # held-out check
```
