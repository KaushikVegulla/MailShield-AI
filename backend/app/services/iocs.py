"""IOC export: analysis indicators as CSV and as a STIX 2.1 bundle.

One row/object per indicator, built from the same analysis the
dashboard and PDF show — nothing is added at export time:

- every analysed URL (body, display-text and QR-decoded), with its
  host as a domain/IP indicator,
- the sender, reply-to and return-path addresses and domains,
- the originating IP from the Received chain,
- attachment file names together with their SHA-256 hashes,
- the SHA-256 of the email itself (the evidence block).

Values are defanged in the CSV (hxxp, [.]) so a spreadsheet of
indicators cannot be clicked by accident. The STIX bundle uses
standard patterning for url / domain-name / ipv4-addr / email-addr /
file hashes, plus SCOs and one observed-data object referencing them.
"""

from __future__ import annotations

import csv
import datetime
import io
import uuid

from app.services.report import defang

_NAMESPACE = uuid.UUID("6d61696c-7368-6965-6c64-616900000001")


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}--{uuid.uuid5(_NAMESPACE, prefix + ':' + value)}"


def build_ioc_rows(analysis: dict) -> list[dict]:
    """Flatten an analysis into indicator rows (raw + defanged)."""
    parsed = analysis["parsed"]
    verdict = analysis.get("verdict") or {}
    score = verdict.get("score")
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None, source: str) -> None:
        if value and (kind, value) not in seen:
            seen.add((kind, value))
            rows.append(
                {
                    "type": kind,
                    "value": value,
                    "defanged": defang(value),
                    "source": source,
                    "score": score,
                    "verdict": verdict.get("verdict"),
                }
            )

    for url in analysis["url_analysis"].get("urls", []):
        source = "qr_code" if url.get("source") == "qr" else "url_analysis"
        add("url", url.get("url"), source)
        host = url.get("host")
        if host:
            add("ip" if host.replace(".", "").isdigit() else "domain", host, source)
    add("ip", parsed.get("originating_ip"), "received_chain")
    for field_name in ("from", "reply_to", "return_path"):
        field = parsed.get(field_name) or {}
        add("email", field.get("email"), f"header_{field_name}")
        add("domain", field.get("domain"), f"header_{field_name}")
    for attachment in parsed.get("attachments") or []:
        add("file_name", attachment.get("filename"), "attachment")
        add("file_sha256", attachment.get("sha256"), "attachment")
    evidence = analysis.get("evidence") or {}
    add("email_sha256", evidence.get("email_sha256"), "evidence_block")
    return rows


def iocs_to_csv(analysis: dict) -> str:
    """CSV with defanged values — safe to open in a spreadsheet."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "defanged_value", "source", "email_score", "email_verdict"])
    for row in build_ioc_rows(analysis):
        writer.writerow([row["type"], row["defanged"], row["source"], row["score"], row["verdict"]])
    return buffer.getvalue()


def _stix_pattern(row: dict) -> str | None:
    value = row["value"].replace("'", "\\'")
    kind = row["type"]
    if kind == "url":
        return f"[url:value = '{value}']"
    if kind == "domain":
        return f"[domain-name:value = '{value}']"
    if kind == "ip":
        return f"[ipv4-addr:value = '{value}']"
    if kind == "email":
        return f"[email-addr:value = '{value}']"
    if kind == "file_sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if kind == "file_name":
        return f"[file:name = '{value}']"
    return None  # email_sha256 is evidence metadata, not a STIX indicator pattern


def _sco_for(row: dict) -> dict | None:
    kind, value = row["type"], row["value"]
    if kind == "url":
        return {"type": "url", "id": _stable_id("url", value), "value": value}
    if kind == "domain":
        return {"type": "domain-name", "id": _stable_id("domain-name", value), "value": value}
    if kind == "ip":
        return {"type": "ipv4-addr", "id": _stable_id("ipv4-addr", value), "value": value}
    if kind == "email":
        return {"type": "email-addr", "id": _stable_id("email-addr", value), "value": value}
    if kind == "file_sha256":
        return {"type": "file", "id": _stable_id("file", value), "hashes": {"SHA-256": value}}
    if kind == "file_name":
        return {"type": "file", "id": _stable_id("file", "name:" + value), "name": value}
    return None


def iocs_to_stix(analysis: dict) -> dict:
    """STIX 2.1 bundle: indicators + SCOs + one observed-data object."""
    now = (analysis.get("evidence") or {}).get("analysed_at_utc") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    rows = build_ioc_rows(analysis)
    objects: list[dict] = []
    sco_refs: list[str] = []
    for row in rows:
        sco = _sco_for(row)
        if sco:
            objects.append(sco)
            sco_refs.append(sco["id"])
        pattern = _stix_pattern(row)
        if pattern:
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": _stable_id("indicator", row["type"] + ":" + row["value"]),
                    "created": now,
                    "modified": now,
                    "name": f"{row['type']}: {row['value']}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "indicator_types": ["malicious-activity"] if (analysis.get("verdict") or {}).get("verdict") == "phishing" else ["unknown"],
                    "labels": [f"source:{row['source']}"],
                }
            )
    if sco_refs:
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": _stable_id("observed-data", (analysis.get("evidence") or {}).get("email_sha256") or "no-hash"),
                "created": now,
                "modified": now,
                "first_observed": now,
                "last_observed": now,
                "number_observed": 1,
                "object_refs": sco_refs,
            }
        )
    return {
        "type": "bundle",
        "id": _stable_id("bundle", (analysis.get("evidence") or {}).get("email_sha256") or "no-hash"),
        "objects": objects,
    }
