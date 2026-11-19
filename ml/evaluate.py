"""Evaluate both candidate models on three different splits.

Writes the real measured results to ml/metrics.json — the only place
MailShield's published metrics come from. Nothing here is estimated;
every number is computed from the downloaded corpora.

Three splits, three different questions:

- **random_stratified** — the original evaluation: stratified 80/20,
  seed 42. Near-duplicates and messages from the same campaign or
  sender can land on both sides, so this is the most optimistic view.
  It is kept (labelled) so the first published run stays comparable.
- **temporal** — train on the earliest 80% of dated messages, test on
  the latest 20%. Asks: does a model trained on older mail still work
  on newer mail? Messages without a parseable Date header are excluded
  from this split only (the count is reported).
- **group_sender_domain** — GroupShuffleSplit on the sender domain
  (falling back to the source file for messages with no From domain),
  so no sender domain appears in both train and test. Asks: does the
  model generalise to senders it has never seen?

Records are deduplicated by full body hash (SHA-256 of the cleaned
subject + body) before any split is made; the number removed is
reported in metrics.json. The previous published run (18 Nov 2026,
prefix-based deduplication, random split only) is preserved in
metrics.json under "previous_published_run" whenever it is found
there, so the original F1 0.9943 stays visible and labelled.
"""

from __future__ import annotations

import datetime
import json
import pathlib

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from dataset import load_records
from train import SEED, build_pipelines

BASE = pathlib.Path(__file__).resolve().parent


def _metrics(y_true, y_pred) -> dict:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def _evaluate_split(texts, labels, train_idx, test_idx) -> dict:
    results = {}
    for name, model in build_pipelines().items():
        model.fit([texts[i] for i in train_idx], [labels[i] for i in train_idx])
        pred = model.predict([texts[i] for i in test_idx])
        results[name] = _metrics([labels[i] for i in test_idx], pred)
        print(f"  {name}: {results[name]}")
    return results


def _split_block(description, train_idx, test_idx, labels, extra=None) -> dict:
    test_phishing = sum(labels[i] for i in test_idx)
    test_legitimate = sum(1 for i in test_idx if labels[i] == 0)
    block = {
        "description": description,
        "train_size": len(train_idx),
        "test_size": len(test_idx),
        "test_phishing": test_phishing,
        "test_legitimate": test_legitimate,
    }
    if min(test_phishing, test_legitimate) < 30:
        block["class_balance_warning"] = (
            f"Test set is heavily imbalanced ({test_phishing} phishing vs {test_legitimate} legitimate): "
            "precision, recall and false-positive rate for the minority class rest on very few messages "
            "and should not be quoted without this context. This happens because the two corpora cover "
            "different periods — SpamAssassin ham is from 2002-2003 while the Nazario phishing corpus "
            "extends years later — so a date-ordered split puts almost only phishing in the newest slice."
        )
    if extra:
        block.update(extra)
    return block


def main() -> None:
    out = BASE / "metrics.json"
    previous = None
    if out.exists():
        try:
            old = json.loads(out.read_text())
            if "previous_published_run" in old:
                # Re-running over our own output: keep the original
                # preserved run instead of preserving ourselves.
                previous = old["previous_published_run"]
            else:
                previous = {
                    "evaluated_on": old.get("evaluated_on"),
                    "dataset_total_emails_used": old.get("dataset", {}).get("total_emails_used"),
                    "deduplication": "400-character text prefix (original method)",
                    "split": old.get("dataset", {}).get("split"),
                    "models": old.get("models"),
                    "selected_model": old.get("selected_model"),
                }
        except Exception:
            previous = None

    records, counts = load_records()
    texts = [r["text"] for r in records]
    labels = [r["label"] for r in records]
    n = len(records)
    dated = sum(1 for r in records if r["date"] is not None)
    print(f"dataset: {counts}, total {n}, dated {dated}")

    splits: dict[str, dict] = {}
    all_idx = list(range(n))

    # --- Random stratified (original split) ---
    print("split: random_stratified")
    train_idx, test_idx = train_test_split(all_idx, test_size=0.2, random_state=SEED, stratify=labels)
    splits["random_stratified"] = _split_block(
        "Stratified 80/20 random split, seed 42. Same sender or campaign can appear on both sides — the optimistic view, kept for comparability with the first published run.",
        train_idx, test_idx, labels,
    )
    splits["random_stratified"]["models"] = _evaluate_split(texts, labels, train_idx, test_idx)

    # --- Temporal (train on older mail, test on newer mail) ---
    print("split: temporal")
    dated_idx = [i for i in all_idx if records[i]["date"] is not None]
    dated_idx.sort(key=lambda i: records[i]["date"])
    cut = int(len(dated_idx) * 0.8)
    t_train, t_test = dated_idx[:cut], dated_idx[cut:]
    date_range = None
    if dated_idx:
        date_range = {
            "earliest": records[dated_idx[0]]["date"].date().isoformat(),
            "test_starts": records[t_test[0]]["date"].date().isoformat() if t_test else None,
            "latest": records[dated_idx[-1]]["date"].date().isoformat(),
        }
    splits["temporal"] = _split_block(
        "Train on the earliest 80% of messages with a parseable Date header, test on the latest 20%. Messages without a usable Date are excluded from this split only.",
        t_train, t_test, labels,
        {"excluded_no_date": n - len(dated_idx), "date_range": date_range},
    )
    splits["temporal"]["models"] = _evaluate_split(texts, labels, t_train, t_test)

    # --- Group split by sender domain ---
    print("split: group_sender_domain")
    groups = [r["sender_domain"] or f"no-from-domain:{r['source_group']}" for r in records]
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    g_train, g_test = next(splitter.split(texts, labels, groups))
    splits["group_sender_domain"] = _split_block(
        "GroupShuffleSplit by sender domain (source file as the group when no From domain exists): no sender domain appears in both train and test.",
        list(g_train), list(g_test), labels,
        {"unique_groups": len(set(groups)), "test_groups": len({groups[i] for i in g_test})},
    )
    splits["group_sender_domain"]["models"] = _evaluate_split(texts, labels, list(g_train), list(g_test))

    random_models = splits["random_stratified"]["models"]
    best = max(random_models, key=lambda name: random_models[name]["f1"])

    metrics = {
        "dataset": {
            "sources": [
                "Nazario Phishing Corpus (monkey.org/~jose/phishing) — phishing",
                "SpamAssassin public corpus easy_ham + hard_ham — legitimate",
            ],
            "total_emails_used": n,
            "phishing": counts["phishing"],
            "legitimate": counts["legitimate"],
            "skipped_empty": counts["skipped_empty"],
            "duplicates_removed": counts["skipped_duplicate"],
            "deduplication": "SHA-256 hash of the full cleaned subject + body text, applied before splitting (the original run deduplicated on a 400-character prefix and removed more near-duplicates)",
            "dated_messages": dated,
            "features": "TF-IDF word n-grams (1,2), max 15000 features, subject + body text only",
        },
        "splits": splits,
        "models": random_models,
        "selected_model": best,
        "evaluated_on": datetime.date.today().isoformat(),
        "note": (
            "All numbers are real measured results on 2002-2007 corpora. The random split is the most "
            "optimistic view; the temporal and sender-domain group splits are harder and closer to how "
            "the model meets new mail. None of these splits measures performance on modern legitimate "
            "mail — use evaluate_heldout.py with a never-trained folder for that."
        ),
    }
    if previous:
        metrics["previous_published_run"] = previous

    out.write_text(json.dumps(metrics, indent=2))
    print(f"wrote {out} (selected on random split: {best})")


if __name__ == "__main__":
    main()
