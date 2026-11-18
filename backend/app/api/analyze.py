"""Analysis endpoints: paste raw email text or upload a .eml file.

This step returns the parsed email and header forensics. URL analysis,
ML scoring and the hybrid verdict are added in later steps and will be
merged into this same response shape.
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from app.core.headers import analyze_headers
from app.core.parser import parse_email

router = APIRouter(prefix="/analyze", tags=["analyze"])


class PasteRequest(BaseModel):
    raw: str


def _result(raw: str | bytes) -> dict:
    parsed = parse_email(raw)
    return {"parsed": parsed, "header_forensics": analyze_headers(parsed)}


@router.post("/email")
def analyze_pasted_email(payload: PasteRequest) -> dict:
    return _result(payload.raw)


@router.post("/eml")
async def analyze_eml_upload(file: UploadFile = File(...)) -> dict:
    contents = await file.read()
    return _result(contents)
