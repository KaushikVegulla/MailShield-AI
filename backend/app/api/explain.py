"""LLM explanation endpoints.

Mirror the report endpoints: the same paste/upload inputs are
analysed deterministically first, then the finished analysis is
optionally narrated by the explainer service. The explanation never
feeds back into the verdict.
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from app.api.analyze import _result
from app.services.explainer import explain_analysis

router = APIRouter(prefix="/explain", tags=["explain"])


class PasteRequest(BaseModel):
    raw: str


@router.post("/email")
def explain_pasted_email(payload: PasteRequest) -> dict:
    return explain_analysis(_result(payload.raw))


@router.post("/eml")
async def explain_eml_upload(file: UploadFile = File(...)) -> dict:
    contents = await file.read()
    return explain_analysis(_result(contents))
