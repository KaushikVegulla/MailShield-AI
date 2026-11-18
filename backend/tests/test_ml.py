"""ML prediction tests.

The trained model artefact is a binary file that is not committed to
GitHub, so these tests skip cleanly when it is absent (fresh clone /
hosted deployment) and run fully where training has been done.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.parser import parse_email
from app.ml.predict import predict_phishing

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
MODEL = pathlib.Path(__file__).resolve().parents[2] / "ml" / "models" / "phishing_pipeline.joblib"


def test_prediction_shape_without_model_is_graceful(tmp_path, monkeypatch):
    import app.ml.predict as predict

    monkeypatch.setattr(predict, "_MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(predict, "_cache", None)
    monkeypatch.setattr(predict, "_load_failed", False)
    result = predict.predict_phishing({"subject": "hi", "body_text": "hello", "body_html": None})
    assert result["model_available"] is False
    assert result["phishing_probability"] is None


@pytest.mark.skipif(not MODEL.exists(), reason="model artefact not present (not committed to GitHub)")
def test_phishing_samples_score_high():
    for name, threshold in (("phishing_paypal.eml", 0.9), ("phishing_bank.eml", 0.85)):
        parsed = parse_email((SAMPLES / name).read_bytes())
        result = predict_phishing(parsed)
        assert result["model_available"] is True
        assert result["phishing_probability"] >= threshold, (name, result)
        assert result["label"] == "phishing"
