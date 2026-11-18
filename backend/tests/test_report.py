"""Forensic PDF report tests."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.main import app

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
client = TestClient(app)


def test_report_pdf_for_phishing_sample():
    raw = (SAMPLES / "phishing_paypal.eml").read_text()
    response = client.post("/report/email", json={"raw": raw})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 1500


def test_report_pdf_via_eml_upload():
    with open(SAMPLES / "legit_college.eml", "rb") as handle:
        response = client.post("/report/eml", files={"file": ("legit_college.eml", handle, "message/rfc822")})
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
