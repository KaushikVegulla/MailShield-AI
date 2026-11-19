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
from app.services.iocs import iocs_to_csv, iocs_to_stix
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


def _ioc_response(analysis: dict, format: str) -> Response:
    if format.lower() == "stix":
        import json

        return Response(
            content=json.dumps(iocs_to_stix(analysis), indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=mailshield-iocs.stix.json"},
        )
    return Response(
        content=iocs_to_csv(analysis),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=mailshield-iocs.csv"},
    )


@router.post("/iocs/email")
def iocs_for_pasted_email(payload: PasteRequest, format: str = "csv") -> Response:
    """IOC export for a pasted email: ?format=csv (default) or stix."""
    return _ioc_response(_result(payload.raw), format)


@router.post("/iocs/eml")
async def iocs_for_eml_upload(file: UploadFile = File(...), format: str = "csv") -> Response:
    contents = await file.read()
    return _ioc_response(_result(contents), format)
