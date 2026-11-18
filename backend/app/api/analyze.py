"""Analysis endpoints: paste raw email text or upload a .eml file.

Returns the full analysis: parsed email, header forensics, URL
analysis, ML prediction, anomaly signals and the hybrid verdict
(rules .50 / ML .35 / anomaly .15) with every reason listed.
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from app.core.anomaly import analyze_anomaly
from app.core.headers import analyze_headers
from app.core.parser import parse_email
from app.core.scoring import score_email
from app.core.urls import analyze_urls
from app.ml.predict import predict_phishing

router = APIRouter(prefix="/analyze", tags=["analyze"])


class PasteRequest(BaseModel):
    raw: str


def _result(raw: str | bytes) -> dict:
    parsed = parse_email(raw)
    header_forensics = analyze_headers(parsed)
    url_analysis = analyze_urls(parsed)
    ml_prediction = predict_phishing(parsed)
    anomaly = analyze_anomaly(parsed)
    return {
        "parsed": parsed,
        "header_forensics": header_forensics,
        "url_analysis": url_analysis,
        "ml_prediction": ml_prediction,
        "anomaly": anomaly,
        "verdict": score_email(parsed, header_forensics, url_analysis, ml_prediction, anomaly),
    }


@router.post("/email")
def analyze_pasted_email(payload: PasteRequest) -> dict:
    return _result(payload.raw)


@router.post("/eml")
async def analyze_eml_upload(file: UploadFile = File(...)) -> dict:
    contents = await file.read()
    return _result(contents)
