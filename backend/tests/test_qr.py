"""QR code decoding tests.

The fixture qr_phishing_url.png is a real QR code encoding
http://185.220.101.47/login (the same bare-IP login URL the PayPal
sample prints as text), generated with the `qrcode` library. Tests
that need a decoder are skipped — not failed — when neither
zxing-cpp nor OpenCV is installed, matching the module's own
optional-dependency behaviour.
"""

import base64
import io
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

from app.core.parser import parse_email
from app.core.qr import _decoder_name, decode_image_bytes, extract_qr_codes
from app.core.urls import analyze_urls

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "qr_phishing_url.png"
QR_URL = "http://185.220.101.47/login"

requires_decoder = pytest.mark.skipif(_decoder_name() is None, reason="no QR decoder installed")


@requires_decoder
def test_decode_fixture_image():
    assert decode_image_bytes(FIXTURE.read_bytes()) == [QR_URL]


def test_decode_non_qr_bytes_is_empty():
    assert decode_image_bytes(b"this is not an image") == []


def _eml_with_qr_attachment() -> bytes:
    encoded = base64.b64encode(FIXTURE.read_bytes()).decode()
    lines = [encoded[i : i + 76] for i in range(0, len(encoded), 76)]
    return (
        "From: IT Helpdesk <helpdesk@example-secure.com>\r\n"
        "Subject: Scan to verify your account\r\n"
        "Date: Tue, 11 Nov 2026 09:02:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        "\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Scan the attached code with your phone to verify your account.\r\n"
        "--BOUND\r\n"
        "Content-Type: image/png; name=\"verify.png\"\r\n"
        "Content-Disposition: attachment; filename=\"verify.png\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n" + "\r\n".join(lines) + "\r\n"
        "--BOUND--\r\n"
    ).encode()


@requires_decoder
def test_qr_attachment_flows_into_url_analysis():
    raw = _eml_with_qr_attachment()
    parsed = parse_email(raw)
    qr = extract_qr_codes(raw, parsed)
    assert qr["available"] is True
    assert qr["urls"] == [QR_URL]
    assert qr["codes"][0]["source"] == "attachment_image"

    url_analysis = analyze_urls(parsed, extra_links=[{"url": u, "display_text": None, "source": "qr"} for u in qr["urls"]])
    assert url_analysis["url_count"] == 1
    entry = url_analysis["urls"][0]
    assert entry["source"] == "qr"
    flag_names = {f["name"] for f in entry["flags"]}
    assert {"ip_host", "http"} <= flag_names
    # Same scoring as a printed bare-IP HTTP link: 25 ip + 10 http
    assert entry["points"] == 35
    assert url_analysis["url_points"] == 35


@requires_decoder
def test_qr_in_pdf_attachment():
    reportlab = pytest.importorskip("reportlab")
    pymupdf = pytest.importorskip("pymupdf")
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.drawImage(str(FIXTURE), 100, 400, width=200, height=200)
    pdf.save()
    pdf_bytes = buffer.getvalue()

    encoded = base64.b64encode(pdf_bytes).decode()
    lines = [encoded[i : i + 76] for i in range(0, len(encoded), 76)]
    raw = (
        "From: IT Helpdesk <helpdesk@example-secure.com>\r\n"
        "Subject: Your verification document\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        "\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Open the attached document and scan the code.\r\n"
        "--BOUND\r\n"
        "Content-Type: application/pdf; name=\"verify.pdf\"\r\n"
        "Content-Disposition: attachment; filename=\"verify.pdf\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n" + "\r\n".join(lines) + "\r\n"
        "--BOUND--\r\n"
    ).encode()

    parsed = parse_email(raw)
    qr = extract_qr_codes(raw, parsed)
    assert qr["urls"] == [QR_URL]
    assert qr["codes"][0]["source"] == "pdf_attachment"


@requires_decoder
def test_no_qr_codes_reports_scanned_and_empty():
    raw = b"From: a@example.com\r\nSubject: Hello\r\n\r\nPlain text, no images."
    parsed = parse_email(raw)
    qr = extract_qr_codes(raw, parsed)
    assert qr["available"] is True
    assert qr["codes"] == []
    assert qr["urls"] == []
