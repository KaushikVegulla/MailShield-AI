"""Evaluate both candidate models on the held-out test split.

Writes the real measured results to ml/metrics.json — the only place
MailShield's published metrics come from. Nothing here is estimated;
every number is computed from the split defined in train.py (seed 42).

Note on scope: these are in-domain held-out metrics on corpora from
2002-2007 (Nazario phishing + SpamAssassin ham). They show the pipeline
learns phishing language, not a guaranteed accuracy on modern mail.
"""

from __future__ import annotations

import datetime
import json
import pathlib

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from dataset import load_dataset
from train import build_pipelines, split_data

BASE = pathlib.Path(__file__).resolve().parent


def _metrics(y_true, y_pred) -> dict:
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }


def main() -> None:
    texts, labels, counts = load_dataset()
    x_train, x_test, y_train, y_test, _ = split_data()

    results = {}
    for name, model in build_pipelines().items():
        model.fit(x_train, y_train)
        results[name] = _metrics(y_test, model.predict(x_test))
        print(name, results[name])

    best = max(results, key=lambda n: results[n]["f1"])
    metrics = {
        "dataset": {
            "sources": [
                "Nazario Phishing Corpus (monkey.org/~jose/phishing) — phishing",
                "SpamAssassin public corpus easy_ham + hard_ham — legitimate",
            ],
            "total_emails_used": len(texts),
            "phishing": counts["phishing"],
            "legitimate": counts["legitimate"],
            "skipped_empty": counts["skipped_empty"],
            "skipped_duplicate": counts["skipped_duplicate"],
            "train_size": len(x_train),
            "test_size": len(x_test),
            "split": "stratified 80/20, random_state=42",
            "features": "TF-IDF word n-grams (1,2), max 15000 features, subject + body text only",
        },
        "models": results,
        "selected_model": best,
        "evaluated_on": datetime.date.today().isoformat(),
        "note": "In-domain held-out metrics on 2002-2007 corpora. Real measured results; not a guarantee of accuracy on modern phishing.",
    }
    out = BASE / "metrics.json"
    out.write_text(json.dumps(metrics, indent=2))
    print(f"wrote {out} (selected: {best})")


if __name__ == "__main__":
    main()
