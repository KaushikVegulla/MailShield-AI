"""Analysis endpoints: paste raw email text or upload a .eml file.

Returns the parsed email, header forensics, URL analysis and the ML
phishing prediction. The hybrid verdict that combines all three is
added in a later step and will be merged into this same response shape.
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from app.core.headers import analyze_headers
from app.core.parser import parse_email
from app.core.urls import analyze_urls
from app.ml.predict import predict_phishing

router = APIRouter(prefix="/analyze", tags=["analyze"])


class PasteRequest(BaseModel):
    raw: str


def _result(raw: str | bytes) -> dict:
    parsed = parse_email(raw)
    return {
        "parsed": parsed,
        "header_forensics": analyze_headers(parsed),
        "url_analysis": analyze_urls(parsed),
        "ml_prediction": predict_phishing(parsed),
    }


@router.post("/email")
def analyze_pasted_email(payload: PasteRequest) -> dict:
    return _result(payload.raw)


@router.post("/eml")
async def analyze_eml_upload(file: UploadFile = File(...)) -> dict:
    contents = await file.read()
    return _result(contents)
