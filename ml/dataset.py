"""Build the labelled dataset from the downloaded corpora.

Phishing = Nazario mbox messages (label 1).
Legitimate = SpamAssassin easy_ham + hard_ham messages (label 0).

Only subject + body text is used (no headers), which keeps the model
focused on message content and avoids it learning routing artefacts.
Texts are deduplicated; the split in train.py is stratified with a
fixed seed, so every run sees the same train/test partition.
"""

from __future__ import annotations

import bz2
import io
import mailbox
import pathlib
import re
import tarfile
from email import policy
from email.parser import BytesParser

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


def load_dataset(min_chars: int = 40) -> tuple[list[str], list[int], dict]:
    texts: list[str] = []
    labels: list[int] = []
    seen: set[str] = set()
    counts = {"phishing": 0, "legitimate": 0, "skipped_empty": 0, "skipped_duplicate": 0}

    def add(text: str, label: int, key: str) -> None:
        if len(text) < min_chars:
            counts["skipped_empty"] += 1
            return
        digest = text[:400]
        if digest in seen:
            counts["skipped_duplicate"] += 1
            return
        seen.add(digest)
        texts.append(text)
        labels.append(label)
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
            add(_message_text(msg), 1, "phishing")

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
                add(_message_text(msg), 0, "legitimate")

    return texts, labels, counts
