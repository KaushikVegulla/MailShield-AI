"""Attachment triage tests — fixtures built in-test, stdlib only."""

import base64
import io
import pathlib
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.api.analyze import _result
from app.core.attachments import analyze_attachments, triage_attachment
from app.core.parser import parse_email

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _zip_bytes(members: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _eml_with_attachment(filename: str, data: bytes, content_type: str = "application/octet-stream") -> bytes:
    encoded = base64.b64encode(data).decode()
    return (
        "From: Sender <sender@example.net>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Invoice attached\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="BB"\r\n\r\n'
        "--BB\r\nContent-Type: text/plain\r\n\r\nPlease see the attached invoice.\r\n"
        f"--BB\r\nContent-Type: {content_type}\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{encoded}\r\n--BB--\r\n"
    ).encode()


def _finding_names(entry):
    return {f["name"] for f in entry["findings"]}


def test_dangerous_and_double_extension():
    entry = triage_attachment("invoice.pdf.exe", b"MZ fake")
    assert {"dangerous_extension", "double_extension"} <= _finding_names(entry)
    assert entry["points"] == 55  # 40 + 15
    plain = triage_attachment("setup.exe", b"MZ fake")
    assert "dangerous_extension" in _finding_names(plain)
    assert "double_extension" not in _finding_names(plain)
    assert plain["points"] == 40


def test_zip_with_executable_member():
    data = _zip_bytes({"readme.txt": "hello", "payload.exe": "MZ fake"})
    entry = triage_attachment("documents.zip", data)
    assert "archive_dangerous_member" in _finding_names(entry)
    assert "payload.exe" in entry["archive_members"]
    assert entry["points"] == 30
    clean = triage_attachment("documents.zip", _zip_bytes({"a.txt": "x"}))
    assert clean["points"] == 0 and clean["findings"] == []


def test_docx_with_vba_project_is_macro_detected():
    data = _zip_bytes({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>", "word/vbaProject.bin": "fake vba"})
    entry = triage_attachment("report.docm", data)
    assert "macro_detected" in _finding_names(entry)
    assert "macro_enabled_type" in _finding_names(entry)
    assert entry["points"] == 50  # 30 macro + 20 macro-enabled type
    clean_docx = triage_attachment("report.docx", _zip_bytes({"word/document.xml": "<w:document/>"}))
    assert clean_docx["points"] == 0


def test_legacy_ole_office_macro_risk_note():
    entry = triage_attachment("old.doc", OLE_MAGIC + b"\x00" * 64)
    assert "legacy_macro_risk" in _finding_names(entry)
    assert entry["points"] == 10


def test_pdf_active_content():
    pdf = b"%PDF-1.4\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF"
    entry = triage_attachment("form.pdf", pdf, "application/pdf")
    assert "pdf_active_content" in _finding_names(entry)
    assert entry["points"] == 25
    plain = triage_attachment("form.pdf", b"%PDF-1.4\nplain content\n%%EOF", "application/pdf")
    assert plain["points"] == 0


def test_end_to_end_attachment_block_and_scoring():
    raw = _eml_with_attachment("invoice.pdf.exe", b"MZ fake")
    result = _result(raw)
    block = result["attachment_analysis"]
    assert block["attachment_count"] == 1
    assert block["attachment_points"] == 55
    assert block["attachments"][0]["sha256"] == parse_email(raw)["attachments"][0]["sha256"]
    sources = {r["source"] for r in result["verdict"]["reasons"]}
    assert "attachment" in sources
    # anomaly channel must not double-score the same attachment
    assert result["verdict"]["components"]["anomaly"]["attachment_points"] == 55


def test_no_attachments_is_clean():
    result = analyze_attachments("Subject: hi\n\nplain", parse_email("Subject: hi\n\nplain"))
    assert result["attachment_count"] == 0
    assert result["attachment_points"] == 0
