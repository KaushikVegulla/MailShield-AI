"""Evaluate the trained model on a folder of emails it never trained on.

This is the held-out harness for data the training corpora cannot
provide — for example a self-built set of modern legitimate mail
(OTPs, receipts, GitHub/Google notifications, newsletters), Phishing
Pot messages, or any other folder of .eml files collected after
training. Nothing is trained here; the saved pipeline is only run.

Usage:

    python evaluate_heldout.py path/to/folder --label phishing
    python evaluate_heldout.py path/to/folder --label legitimate
    python evaluate_heldout.py ../samples --label from-filename
    python evaluate_heldout.py path/to/folder --label phishing --out results.json

--label applies to every file in the folder, except with
``from-filename`` where a file whose name starts with ``phishing``
counts as phishing and one starting with ``legit`` as legitimate
(the naming the repo's samples/ folder uses); other names are skipped.

For every file the harness also checks — when the training corpora are
present in ml/data/ — whether its body hash appears in the training
data, so a "held-out" file that was actually trained on is flagged
instead of quietly inflating the score. When the corpora are absent
the check is reported as unavailable, never assumed.

Requires a trained model at ml/models/phishing_pipeline.joblib
(run train.py first). Exits with code 2 and a clear message if the
model is missing — it never invents a result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from email import policy
from email.parser import BytesParser

BASE = pathlib.Path(__file__).resolve().parent
DEFAULT_MODEL = BASE / "models" / "phishing_pipeline.joblib"


def _file_label(path: pathlib.Path, mode: str) -> int | None:
    if mode == "phishing":
        return 1
    if mode == "legitimate":
        return 0
    name = path.name.lower()
    if name.startswith("phishing"):
        return 1
    if name.startswith("legit"):
        return 0
    return None


def _training_hashes() -> set[str] | None:
    data_dir = BASE / "data"
    if not data_dir.exists() or not any(data_dir.iterdir()):
        return None
    from dataset import load_records

    records, _ = load_records()
    return {r["body_hash"] for r in records}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=pathlib.Path, help="Folder of .eml files to evaluate")
    parser.add_argument("--label", choices=["phishing", "legitimate", "from-filename"], required=True)
    parser.add_argument("--model", type=pathlib.Path, default=DEFAULT_MODEL)
    parser.add_argument("--out", type=pathlib.Path, default=None, help="Optional path to write JSON results")
    args = parser.parse_args()

    if not args.folder.is_dir():
        print(f"error: {args.folder} is not a directory")
        return 2
    if not args.model.exists():
        print(
            f"error: trained model not found at {args.model}. "
            "Run download_data.py and train.py first — no result can be produced without it."
        )
        return 2

    import joblib

    from dataset import _message_text

    bundle = joblib.load(args.model)
    pipeline = bundle["pipeline"]

    print("checking held-out files against the training corpora (body hash) ...")
    training_hashes = _training_hashes()
    overlap_check = "available" if training_hashes is not None else "unavailable (training corpora not in ml/data/)"

    files = sorted(p for p in args.folder.rglob("*.eml") if p.is_file())
    results = []
    skipped = []
    for path in files:
        label = _file_label(path, args.label)
        if label is None:
            skipped.append(path.name)
            continue
        try:
            msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            text = _message_text(msg)
        except Exception as exc:  # unreadable file: report, don't guess
            skipped.append(f"{path.name} (unreadable: {exc})")
            continue
        body_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        probability = float(pipeline.predict_proba([text])[0][1])
        results.append(
            {
                "file": path.name,
                "true_label": "phishing" if label == 1 else "legitimate",
                "body_sha256": body_hash,
                "in_training_corpus": (body_hash in training_hashes) if training_hashes is not None else None,
                "phishing_probability": round(probability, 4),
                "predicted_label": "phishing" if probability >= 0.5 else "legitimate",
            }
        )

    tp = sum(1 for r in results if r["true_label"] == "phishing" and r["predicted_label"] == "phishing")
    fn = sum(1 for r in results if r["true_label"] == "phishing" and r["predicted_label"] != "phishing")
    tn = sum(1 for r in results if r["true_label"] == "legitimate" and r["predicted_label"] == "legitimate")
    fp = sum(1 for r in results if r["true_label"] == "legitimate" and r["predicted_label"] != "legitimate")
    total = len(results)
    summary = {
        "files_evaluated": total,
        "skipped": skipped,
        "overlap_check": overlap_check,
        "files_found_in_training_corpus": sum(1 for r in results if r["in_training_corpus"]),
        "accuracy": round((tp + tn) / total, 4) if total else None,
        "false_positive_rate_on_legitimate": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "false_negative_rate_on_phishing": round(fn / (fn + tp), 4) if (fn + tp) else None,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }
    output = {
        "folder": str(args.folder),
        "model": str(args.model),
        "model_name": bundle.get("model_name"),
        "summary": summary,
        "files": results,
        "note": "Held-out check only — this folder was not used for training or for any split in evaluate.py. Small folders illustrate behaviour; they are not a benchmark.",
    }
    print(json.dumps(summary, indent=2))
    for r in results:
        print(f"  {r['file']}: true={r['true_label']} predicted={r['predicted_label']} p={r['phishing_probability']} in_training={r['in_training_corpus']}")
    if args.out:
        args.out.write_text(json.dumps(output, indent=2))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
