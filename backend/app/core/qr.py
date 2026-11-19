"""QR code decoding for image and PDF content in an email.

Quishing (QR-code phishing) hides the malicious link inside an image
so text and link scanners never see a URL. This module decodes QR
codes from:

- image attachments (png / jpg / gif / bmp / webp),
- images embedded in the message body (inline MIME parts and
  ``data:`` URIs in the HTML body),
- PDF attachments (pages are rendered and scanned, which also covers
  images embedded in the PDF).

Decoded texts that are http(s) URLs are handed to the normal URL
analysis (see app.core.urls) and marked with source "qr" there, so a
QR link scores exactly like a link printed in the body.

Decoder: zxing-cpp is preferred — it ships as a self-contained wheel
with no system library (pyzbar would need the zbar shared library,
which hosted environments such as Render do not provide). OpenCV's
QRCodeDetector is used if it happens to be installed and zxing-cpp is
not. PyMuPDF (also a self-contained wheel) renders PDF pages. If no
decoder is available the analysis still runs: the result reports
``available: False`` instead of guessing.
"""

from __future__ import annotations

import base64
import io
import re
from email import policy
from email.parser import BytesParser, Parser

DATA_URI_RE = re.compile(r"data:image/[a-zA-Z0-9.+-]+;base64,([A-Za-z0-9+/=\s]+)")
IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp", "image/tiff"}


def _decoder_name() -> str | None:
    try:
        import zxingcpp  # noqa: F401

        return "zxing-cpp"
    except Exception:
        pass
    try:
        import cv2  # noqa: F401

        return "opencv"
    except Exception:
        return None


def decode_image_bytes(data: bytes) -> list[str]:
    """Decode every QR code in one image's bytes. Returns code texts."""
    if not data:
        return []
    name = _decoder_name()
    if name is None:
        return []
    try:
        from PIL import Image

        image = Image.open(io.BytesIO(data))
        image.load()
    except Exception:
        return []

    texts: list[str] = []
    if name == "zxing-cpp":
        try:
            import zxingcpp

            results = zxingcpp.read_barcodes(image)
            for result in results:
                text = getattr(result, "text", None)
                if text and text not in texts:
                    texts.append(text)
            return texts
        except Exception:
            return []
    # OpenCV fallback
    try:
        import cv2
        import numpy as np

        array = np.array(image.convert("RGB"))
        detector = cv2.QRCodeDetector()
        try:
            ok, decoded, _points, _ = detector.detectAndDecodeMulti(array)
            if ok:
                texts.extend(t for t in decoded if t)
        except Exception:
            text, _points, _ = detector.detectAndDecode(array)
            if text:
                texts.append(text)
    except Exception:
        return []
    return texts


def _decode_pdf_bytes(data: bytes, filename: str | None) -> list[dict]:
    """Render each PDF page and decode QR codes from the renderings."""
    codes: list[dict] = []
    try:
        import pymupdf
    except Exception:
        try:
            import fitz as pymupdf  # older PyMuPDF import name
        except Exception:
            return codes
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception:
        return codes
    try:
        for page in doc:
            try:
                pixmap = page.get_pixmap(dpi=200)
                image_bytes = pixmap.tobytes("png")
            except Exception:
                continue
            for text in decode_image_bytes(image_bytes):
                codes.append({"text": text, "source": "pdf_attachment", "filename": filename})
    finally:
        doc.close()
    return codes


def _codes_from_mime(raw: str | bytes) -> list[dict]:
    codes: list[dict] = []
    try:
        if isinstance(raw, bytes):
            msg = BytesParser(policy=policy.default).parsebytes(raw)
        else:
            msg = Parser(policy=policy.default).parsestr(raw)
    except Exception:
        return codes
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue
        if content_type in IMAGE_TYPES or (filename and filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"))):
            disposition = (part.get_content_disposition() or "").lower()
            source = "attachment_image" if (disposition == "attachment" or filename) else "embedded_image"
            for text in decode_image_bytes(payload):
                codes.append({"text": text, "source": source, "filename": filename})
        elif content_type == "application/pdf" or (filename and filename.lower().endswith(".pdf")):
            codes.extend(_decode_pdf_bytes(payload, filename))
    return codes


def _codes_from_html(parsed: dict) -> list[dict]:
    codes: list[dict] = []
    html = parsed.get("body_html") or ""
    for match in DATA_URI_RE.findall(html):
        try:
            data = base64.b64decode(re.sub(r"\s+", "", match))
        except Exception:
            continue
        for text in decode_image_bytes(data):
            codes.append({"text": text, "source": "html_data_uri", "filename": None})
    return codes


def extract_qr_codes(raw: str | bytes, parsed: dict) -> dict:
    """Find and decode QR codes anywhere in the email.

    Returns the decoder status, every decoded code with where it was
    found, and the subset of decoded texts that are http(s) URLs —
    those are what the URL analysis consumes.
    """
    decoder = _decoder_name()
    if decoder is None:
        return {
            "available": False,
            "decoder": None,
            "codes": [],
            "urls": [],
            "note": "No QR decoder installed (zxing-cpp or OpenCV) — QR codes in images/PDFs were not scanned.",
        }
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for code in _codes_from_mime(raw) + _codes_from_html(parsed):
        key = (code["text"], code["source"])
        if key not in seen:
            seen.add(key)
            found.append(code)
    urls = []
    for code in found:
        text = code["text"].strip()
        if text.lower().startswith(("http://", "https://")) and text not in urls:
            urls.append(text)
    return {
        "available": True,
        "decoder": decoder,
        "codes": found,
        "urls": urls,
        "note": None if found else "QR scanning ran; no QR codes were found in image or PDF content.",
    }
