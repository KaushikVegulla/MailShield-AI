# ML pipeline

Classifier for phishing email text (subject + body).

## Dataset

Planned: Kaggle Phishing Email Dataset, built from the Nazario phishing corpus and legitimate corpora (Enron and others), labelled phishing / legitimate.
Fallback if the Kaggle download is unavailable: Nazario phishing corpus + Enron ham, downloaded directly from their public sources and combined with the same labelling code.

No synthetic dataset will be used for reported metrics.

## Approach

- TF-IDF features over subject + body text
- Baseline: Logistic Regression
- Comparison: XGBoost
- Held-out test split; `evaluate.py` writes real accuracy / precision / recall / F1 to `metrics.json`

## Status

Training pipeline not yet run. `metrics.json` will only appear once it is generated from a real run.
