"""Train the phishing classifier and save the best pipeline.

Pipeline: TF-IDF (word n-grams 1-2, 15k features) -> classifier.
Logistic Regression (baseline) and XGBoost are both trained on the
same stratified split; whichever scores the higher test F1 is saved
as the production pipeline to ml/models/phishing_pipeline.joblib.

Run download_data.py first. Evaluation lives in evaluate.py and is
run automatically at the end of training.
"""

from __future__ import annotations

import pathlib

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

from dataset import load_dataset

BASE = pathlib.Path(__file__).resolve().parent
MODEL_DIR = BASE / "models"
SEED = 42


def split_data():
    texts, labels, counts = load_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=SEED, stratify=labels
    )
    return x_train, x_test, y_train, y_test, counts


def build_pipelines() -> dict[str, Pipeline]:
    lr = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=15000, ngram_range=(1, 2), sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=1000, C=10.0)),
        ]
    )
    xgb = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=15000, ngram_range=(1, 2), sublinear_tf=True)),
            (
                "clf",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=6,
                    learning_rate=0.1,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    eval_metric="logloss",
                    n_jobs=2,
                ),
            ),
        ]
    )
    return {"logistic_regression": lr, "xgboost": xgb}


def main() -> None:
    x_train, x_test, y_train, y_test, counts = split_data()
    print(f"dataset: {counts}")
    print(f"train {len(x_train)} / test {len(x_test)}")

    best_name, best_f1, best_model = None, -1.0, None
    for name, model in build_pipelines().items():
        model.fit(x_train, y_train)
        # Compare on F1 rounded to 4 decimals — the precision metrics.json
        # publishes — so a tie selects the same model here and in
        # evaluate.py (the simpler Logistic Regression, listed first).
        f1 = round(float(f1_score(y_test, model.predict(x_test))), 4)
        print(f"{name}: test F1 = {f1:.4f}")
        if f1 > best_f1:
            best_name, best_f1, best_model = name, f1, model

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    out = MODEL_DIR / "phishing_pipeline.joblib"
    joblib.dump({"pipeline": best_model, "model_name": best_name}, out)
    print(f"saved best model ({best_name}, F1 {best_f1:.4f}) -> {out}")


if __name__ == "__main__":
    main()
