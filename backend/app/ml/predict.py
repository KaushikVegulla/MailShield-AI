"""ML phishing prediction using the trained model in ml/.

The model artefact (ml/models/phishing_pipeline.joblib) is a binary
file and is not committed to GitHub, so it may be absent — locally
after training, or on a hosted deployment that does not ship it.
In that case prediction returns model_available=False and the rest
of the analysis (headers + URLs) still works. This mirrors how
ShieldNet's hosted backend behaves without its model files.
"""

from __future__ import annotations

import pathlib

_MODEL_PATH = (
    pathlib.Path(__file__).resolve().parents[3] / "ml" / "models" / "phishing_pipeline.joblib"
)

_cache: dict | None = None
_load_failed = False


def _load() -> dict | None:
    global _cache, _load_failed
    if _cache is not None:
        return _cache
    if _load_failed:
        return None
    try:
        import joblib

        _cache = joblib.load(_MODEL_PATH)
    except Exception:
        _load_failed = True
        return None
    return _cache


def predict_phishing(parsed: dict) -> dict:
    """Score a parsed email's subject + body with the trained pipeline."""
    bundle = _load()
    if bundle is None:
        return {
            "model_available": False,
            "model_name": None,
            "phishing_probability": None,
            "ml_points": None,
            "label": None,
        }
    import re

    html_text = re.sub(r"<[^>]+>", " ", parsed.get("body_html") or "")
    text = " ".join(
        part for part in [parsed.get("subject") or "", parsed.get("body_text") or "", html_text] if part
    ).strip()
    pipeline = bundle["pipeline"]
    probability = float(pipeline.predict_proba([text])[0][1])
    return {
        "model_available": True,
        "model_name": bundle.get("model_name"),
        "phishing_probability": round(probability, 4),
        "ml_points": int(round(probability * 100)),
        "label": "phishing" if probability >= 0.5 else "legitimate",
    }
