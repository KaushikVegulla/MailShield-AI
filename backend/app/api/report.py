"""Forensic PDF report endpoints.

Stateless: the report endpoints re-run the same analysis as /analyze
and render it as a downloadable PDF, so a report always matches the
verdict the analyst saw.
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from app.api.analyze import _result
from app.services.report import generate_report_pdf

router = APIRouter(prefix="/report", tags=["report"])


class PasteRequest(BaseModel):
    raw: str


def _pdf_response(analysis: dict) -> Response:
    pdf = generate_report_pdf(analysis)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=mailshield-forensic-report.pdf"},
    )


@router.post("/email")
def report_for_pasted_email(payload: PasteRequest) -> Response:
    return _pdf_response(_result(payload.raw))


@router.post("/eml")
async def report_for_eml_upload(file: UploadFile = File(...)) -> Response:
    contents = await file.read()
    return _pdf_response(_result(contents))
