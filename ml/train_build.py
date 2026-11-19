"""Train the ML model during a hosted build (Render).

The model artefact is a binary file and is deliberately not
committed to git, so a fresh clone — including the Render build —
has no model and the backend scores without its ML component. This
script closes that gap at build time: it downloads the same public
corpora as ``download_data.py`` (skipping files that already exist),
builds the dataset with the same full-hash deduplication as
``dataset.py``, trains the TF-IDF + Logistic Regression pipeline
exactly as defined in ``train.py``, and saves the artefact to the
path ``backend/app/ml/predict.py`` loads from
(``ml/models/phishing_pipeline.joblib``).

The Render build command guards this script with ``|| echo`` so a
training failure (for example, a corpus host being unreachable) can
never fail the deploy — the backend simply runs without the ML
component, exactly as it did before, and /health reports the model
as absent.
"""

from __future__ import annotations

import pathlib
import sys
import time

BASE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import download_data  # noqa: E402
from dataset import load_dataset  # noqa: E402


def main() -> int:
    started = time.monotonic()
    print("[train_build] downloading corpora (existing files are skipped)")
    download_data.main()

    print("[train_build] building dataset (full-hash dedup, as in dataset.py)")
    texts, labels, counts = load_dataset()
    print(f"[train_build] dataset counts: {counts}")
    if len(texts) < 1000:
        print(f"[train_build] ERROR: only {len(texts)} usable emails — refusing to train on a stub dataset")
        return 1

    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    # Same split discipline and the same Logistic Regression pipeline
    # definition as train.py (which also races XGBoost for the local
    # artefact; the build trains the selected model only — Logistic
    # Regression won the comparison in both published runs, and it
    # keeps the hosted build fast).
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=15000, ngram_range=(1, 2), sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=1000, C=10.0)),
        ]
    )
    pipeline.fit(x_train, y_train)
    f1 = float(f1_score(y_test, pipeline.predict(x_test)))
    print(f"[train_build] logistic_regression held-out random-split F1 = {f1:.4f} (train {len(x_train)} / test {len(x_test)})")

    out_dir = BASE / "models"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "phishing_pipeline.joblib"
    joblib.dump({"pipeline": pipeline, "model_name": "logistic_regression"}, out)
    elapsed = time.monotonic() - started
    print(f"[train_build] saved model -> {out} ({out.stat().st_size} bytes) in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
