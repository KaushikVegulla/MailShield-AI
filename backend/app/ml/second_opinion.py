"""Optional transformer second opinion — advisory only, never scored.

A pre-trained DistilBERT-class phishing classifier can be enabled as
a *second opinion* next to the hybrid verdict. It is deliberately
kept out of the scoring path: the hybrid score is computed without
it, and this block is attached afterwards for the analyst to compare.
Disagreement is information, not an override.

Gates (both must pass before anything loads):

- ``SECOND_OPINION_MODEL`` env var names the HuggingFace model;
  unset (the default everywhere, including the hosted deployment)
  means the feature is off and this module returns immediately.
- ``transformers`` / ``torch`` are optional dependencies, imported
  lazily. They are NOT in the default requirements (they would add
  gigabytes to a free-tier build); see ``backend/requirements-ml.txt``.

Default model when the operator enables the feature (set
``SECOND_OPINION_MODEL`` to this id): ``cybersectony/phishing-email-
detection-distilbert_v2.4.1`` — a DistilBERT fine-tune whose model
card defines four classes over emails and URLs:
``legitimate_email``, ``phishing_url``, ``legitimate_url``,
``phishing_url_alt``. The reported phishing probability is the sum
of the two phishing classes; all four raw class probabilities are
returned so nothing is hidden by that mapping.
"""

from __future__ import annotations

import os
import re

# Class index -> name, per the model card of the default model.
DEFAULT_CLASS_LABELS = {
    0: "legitimate_email",
    1: "phishing_url",
    2: "legitimate_url",
    3: "phishing_url_alt",
}
PHISHING_CLASSES = {"phishing_url", "phishing_url_alt"}

_cache: dict | None = None
_load_error: str | None = None


def _get_classifier(model_name: str):
    """Load (once) and return a callable text -> {label: probability}.

    Raises on any failure; callers fail open. Kept as a single seam
    so tests can stub the pipeline without torch installed.
    """
    global _cache, _load_error
    if _cache is not None and _cache.get("model") == model_name:
        return _cache["classify"]
    if _load_error is not None and (_cache or {}).get("model") == model_name:
        raise RuntimeError(_load_error)
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        model.eval()
        id2label = getattr(model.config, "id2label", None) or DEFAULT_CLASS_LABELS

        def classify(text: str) -> dict[str, float]:
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                outputs = model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()
            return {str(id2label.get(i, f"LABEL_{i}")): round(float(p), 4) for i, p in enumerate(probs)}

        # The model card's semantic names are clearer than LABEL_0..3;
        # translate when the config carries the generic names.
        def classify_named(text: str) -> dict[str, float]:
            raw = classify(text)
            named = {}
            for label, prob in raw.items():
                if label.startswith("LABEL_"):
                    try:
                        idx = int(label.split("_", 1)[1])
                        named[DEFAULT_CLASS_LABELS.get(idx, label)] = prob
                        continue
                    except (ValueError, IndexError):
                        pass
                named[label] = prob
            return named

        _cache = {"model": model_name, "classify": classify_named}
        _load_error = None
        return classify_named
    except Exception as exc:
        _load_error = f"{type(exc).__name__}: {exc}"
        _cache = {"model": model_name, "classify": None}
        raise


def _message_text(parsed: dict) -> str:
    html_text = re.sub(r"<[^>]+>", " ", parsed.get("body_html") or "")
    return " ".join(
        part for part in [parsed.get("subject") or "", parsed.get("body_text") or "", html_text] if part
    ).strip()


def second_opinion(parsed: dict) -> dict:
    """Return the transformer second opinion block for one email."""
    model_name = os.environ.get("SECOND_OPINION_MODEL")
    if not model_name:
        return {"available": False, "reason": "SECOND_OPINION_MODEL not set — transformer second opinion is disabled"}
    try:
        classify = _get_classifier(model_name)
        probabilities = classify(_message_text(parsed))
    except Exception as exc:  # fail-open: advisory feature, never blocks analysis
        return {"available": False, "reason": f"second opinion unavailable: {type(exc).__name__}: {exc}", "model": model_name}
    phishing = round(sum(p for label, p in probabilities.items() if label in PHISHING_CLASSES), 4)
    top_label = max(probabilities.items(), key=lambda kv: kv[1])[0] if probabilities else None
    return {
        "available": True,
        "model": model_name,
        "top_label": top_label,
        "phishing_probability": phishing,
        "class_probabilities": probabilities,
        "note": "Advisory second opinion from a pre-trained transformer. It never feeds the hybrid score; the verdict stands on rules + TF-IDF ML + anomaly evidence alone.",
    }
