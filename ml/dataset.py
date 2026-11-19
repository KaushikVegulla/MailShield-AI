"""Build the labelled dataset from the downloaded corpora.

Phishing = Nazario mbox messages (label 1).
Legitimate = SpamAssassin easy_ham + hard_ham messages (label 0).

Only subject + body text is used for the model features (no headers),
which keeps the model focused on message content and avoids it learning
routing artefacts. Alongside the text, each record keeps the metadata
the evaluation splits need: the message date, the sender domain, the
source file it came from, and a SHA-256 hash of the cleaned text.

Deduplication is by that full body hash (SHA-256 of the cleaned
subject + body), applied before any split is made. The earlier pipeline
deduplicated on a 400-character text prefix; the full-hash method only
removes exact duplicates, so counts differ from the first published run
— metrics.json keeps that original run labelled separately.
"""

from __future__ import annotations

import bz2
import datetime
import hashlib
import io
import mailbox
import pathlib
import re
import tarfile
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def _clean(text: str) -> str:
    text = TAG_RE.sub(" ", text)
    return WS_RE.sub(" ", text).strip()


def _message_text(msg) -> str:
    subject = str(msg.get("Subject") or "")
    bodies: list[str] = []
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            bodies.append(payload.decode(charset, errors="replace"))
        except (LookupError, UnicodeError):
            bodies.append(payload.decode("utf-8", errors="replace"))
    return _clean(f"{subject}\n{' '.join(bodies)}")


def _raw_header(msg, name: str) -> str | None:
    """Raw header value without structured parsing.

    Some messages in these old corpora have malformed From/Date headers
    that make the default policy's structured header parsing raise, so
    metadata extraction works on the raw strings instead.
    """
    try:
        for key, value in msg.raw_items():
            if key.lower() == name.lower():
                return str(value)
    except Exception:
        return None
    return None


def _message_date(msg):
    raw = _raw_header(msg, "Date")
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(str(raw))
    except (TypeError, ValueError):
        return None
    if dt is not None and dt.tzinfo is None:
        # Old corpora mix zone-less and zoned Date headers; assume UTC
        # for the zone-less ones so dates stay comparable for sorting.
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _sender_domain(msg) -> str | None:
    _, addr = parseaddr(_raw_header(msg, "From") or "")
    addr = addr.strip().lower()
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip(" <>") or None


def load_records(min_chars: int = 40) -> tuple[list[dict], dict]:
    """Load deduplicated records with split metadata.

    Returns (records, counts). Each record: text, label (1 phishing /
    0 legitimate), date (datetime or None), sender_domain, source_group
    (which corpus file it came from) and body_hash (SHA-256 of text).
    """
    records: list[dict] = []
    seen: set[str] = set()
    counts = {"phishing": 0, "legitimate": 0, "skipped_empty": 0, "skipped_duplicate": 0}

    def add(msg, label: int, key: str, source_group: str) -> None:
        text = _message_text(msg)
        if len(text) < min_chars:
            counts["skipped_empty"] += 1
            return
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        if digest in seen:
            counts["skipped_duplicate"] += 1
            return
        seen.add(digest)
        records.append(
            {
                "text": text,
                "label": label,
                "date": _message_date(msg),
                "sender_domain": _sender_domain(msg),
                "source_group": source_group,
                "body_hash": digest,
            }
        )
        counts[key] += 1

    # Phishing: Nazario mbox files
    for mbox_path in sorted(DATA_DIR.glob("phishing*.mbox")):
        box = mailbox.mbox(str(mbox_path))
        for raw_msg in box:
            # mailbox gives email.message.Message; convert via bytes for policy parsing
            try:
                msg = BytesParser(policy=policy.default).parsebytes(raw_msg.as_bytes())
            except Exception:
                continue
            add(msg, 1, "phishing", f"nazario:{mbox_path.name}")

    # Legitimate: SpamAssassin ham archives (each member is one message)
    for archive_name in ("easy_ham.tar.bz2", "hard_ham.tar.bz2"):
        archive_path = DATA_DIR / archive_name
        if not archive_path.exists():
            continue
        raw = bz2.decompress(archive_path.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                try:
                    msg = BytesParser(policy=policy.default).parsebytes(handle.read())
                except Exception:
                    continue
                add(msg, 0, "legitimate", f"spamassassin:{archive_name.removesuffix('.tar.bz2')}")

    return records, counts


def load_dataset(min_chars: int = 40) -> tuple[list[str], list[int], dict]:
    """Backwards-compatible (texts, labels, counts) view of load_records."""
    records, counts = load_records(min_chars=min_chars)
    return [r["text"] for r in records], [r["label"] for r in records], counts
