"""scan.jsonl output -- one object per service, structured fields preserved."""
import json
import os
import tempfile

from servicescan import formats
from servicescan.models import CVE, Host, Service, ScanResult


def _result():
    svc = Service(port=9801, proto="tcp", state="open", name="http",
                  product="Golang net/http server", confidence="medium",
                  extrainfo="UNAUTHENTICATED")
    svc.http = {"server": "MinIO", "title": "MinIO Console",
                "tech": ["minio"]}
    svc.scripts = [{"id": "minio-auth",
                    "output": "MinIO detected; authentication is enforced."}]
    svc.cves = [CVE(id="CVE-2000-0001", source="nvd", cvss=5.0,
                    severity="MEDIUM", summary="x", url="https://x")]
    host = Host(target="10.0.0.9", ip="10.0.0.9", services=[svc])
    return ScanResult(target="10.0.0.9", hosts=[host])


def _write_and_load():
    d = tempfile.mkdtemp()
    formats.write_jsonl(d, _result())
    with open(os.path.join(d, "scan.jsonl"), encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def test_jsonl_carries_http_title_scripts_and_extrainfo():
    rows = _write_and_load()
    assert len(rows) == 1
    row = rows[0]
    # the fingerprinted page title lives under http and must survive export
    assert row["http"]["title"] == "MinIO Console"
    assert row["http"]["server"] == "MinIO"
    assert row["extrainfo"] == "UNAUTHENTICATED"
    assert row["scripts"][0]["id"] == "minio-auth"
    assert row["cves"][0]["id"] == "CVE-2000-0001"


def test_html_shows_page_title():
    d = tempfile.mkdtemp()
    formats.write_html(d, _result())
    with open(os.path.join(d, "report.html"), encoding="utf-8") as fh:
        doc = fh.read()
    assert "MinIO Console" in doc
    assert "stitle" in doc          # rendered via the dedicated title span
