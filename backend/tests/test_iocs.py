"""IOC export tests: CSV and STIX 2.1 on the PayPal phishing sample."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from app.api.analyze import _result
from app.main import app
from app.services.iocs import build_ioc_rows, iocs_to_csv, iocs_to_stix

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
client = TestClient(app)


def _paypal():
    return _result((SAMPLES / "phishing_paypal.eml").read_bytes())


def test_csv_contains_defanged_phishing_url_and_indicators():
    csv_text = iocs_to_csv(_paypal())
    assert "hxxp://185[.]220[.]101[.]47/login/verify" in csv_text
    assert "paypa1-secure-login[.]com" in csv_text
    assert "email_sha256" in csv_text
    # nothing clickable survives defanging in the value column
    assert "http://185" not in csv_text


def test_rows_cover_expected_types():
    rows = build_ioc_rows(_paypal())
    types = {r["type"] for r in rows}
    assert {"url", "ip", "domain", "email", "email_sha256"} <= types
    ip_rows = [r for r in rows if r["type"] == "ip"]
    assert any(r["value"] == "185.220.101.47" for r in ip_rows)


def test_stix_bundle_structure_and_patterns():
    bundle = iocs_to_stix(_paypal())
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert {"indicator", "observed-data", "url", "ipv4-addr", "domain-name", "email-addr"} <= types
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert any("[ipv4-addr:value = '185.220.101.47']" in p for p in patterns)
    assert any("[url:value = 'http://185.220.101.47/login/verify']" in p for p in patterns)
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    assert observed["number_observed"] == 1 and observed["object_refs"]
    json.dumps(bundle)  # must be JSON-serialisable


def test_ioc_endpoints_csv_and_stix():
    raw = (SAMPLES / "phishing_paypal.eml").read_text()
    response = client.post("/report/iocs/email", json={"raw": raw})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "hxxp://185[.]220[.]101[.]47" in response.text

    response = client.post("/report/iocs/email?format=stix", json={"raw": raw})
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["type"] == "bundle"

    with open(SAMPLES / "phishing_paypal.eml", "rb") as handle:
        response = client.post("/report/iocs/eml?format=csv", files={"file": ("phishing_paypal.eml", handle, "message/rfc822")})
    assert response.status_code == 200
