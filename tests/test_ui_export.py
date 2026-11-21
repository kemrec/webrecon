"""webrecon_ui.server: /api/export/<scan_id>/<fmt> download endpoints.

A scan is cached server-side under a scan_id; the export endpoint re-renders any
of servicescan's output files (via report.write_all into a temp dir) for that
same scan -- no re-scan. run_scan is monkeypatched so nothing touches the network.
"""
import threading
import contextlib

import httpx
import pytest

from webrecon_ui import server
from servicescan.models import ScanResult, Host, Service, CVE


@contextlib.contextmanager
def _running_server():
    httpd = server.make_server("127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        _, port = httpd.server_address
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


def _canned_result():
    web = Service(port=443, proto="tcp", state="open", name="https", product="nginx",
                  version="1.18.0")
    web.sources = ["nmap"]
    web.cves.append(CVE(id="CVE-2021-23017", source="nvd", cvss=9.8, severity="CRITICAL",
                        summary="resolver off-by-one", url="https://x/CVE-2021-23017"))
    smb = Service(port=445, proto="tcp", state="open", name="microsoft-ds", product="SMB")
    smb.sources = ["exposure"]
    smb.scripts.append({"id": "smb-signing-not-required", "output": "relay risk"})
    host = Host(target="10.0.0.5", ip="10.0.0.5", services=[web, smb])
    return ScanResult(target="10.0.0.5", hosts=[host], nmap_used=True)


@contextlib.contextmanager
def _scanned(monkeypatch):
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"target": "10.0.0.5"}, timeout=5)
        assert r.status_code == 200
        sid = r.json()["scan_id"]
        assert sid
        yield base, sid


def test_scan_response_carries_scan_id(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        assert isinstance(sid, str) and len(sid) >= 8


def test_export_json_is_downloadable(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        r = httpx.get(f"{base}/api/export/{sid}/json", timeout=5)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert 'filename="scan.json"' in r.headers.get("content-disposition", "")
    assert r.json()["target"] == "10.0.0.5"


def test_export_csv_and_html_and_sarif(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        csv = httpx.get(f"{base}/api/export/{sid}/services-csv", timeout=5)
        html = httpx.get(f"{base}/api/export/{sid}/html", timeout=5)
        sarif = httpx.get(f"{base}/api/export/{sid}/sarif", timeout=5)
    assert csv.status_code == 200 and csv.headers["content-type"].startswith("text/csv")
    assert "host,hostname,port" in csv.text
    assert "445" in csv.text
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert "<html" in html.text.lower()
    assert sarif.status_code == 200
    assert sarif.json()["version"] == "2.1.0"


def test_export_nuclei_web_and_net(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        web = httpx.get(f"{base}/api/export/{sid}/nuclei-web", timeout=5)
        net = httpx.get(f"{base}/api/export/{sid}/nuclei-net", timeout=5)
    # 443/https is a web target -> scheme://host:port
    assert web.status_code == 200
    assert "https://10.0.0.5:443" in web.text
    # 445/microsoft-ds is non-web -> host:port
    assert net.status_code == 200
    assert "10.0.0.5:445" in net.text


def test_export_unknown_format_is_400(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        r = httpx.get(f"{base}/api/export/{sid}/../server.py", timeout=5)
        r2 = httpx.get(f"{base}/api/export/{sid}/bogus", timeout=5)
    # a traversal-looking fmt is just an unknown token (the filename comes from a
    # fixed table, never the request), so it is rejected, not resolved
    assert r.status_code in (400, 404)
    assert r2.status_code == 400
    assert "format" in r2.json()["error"]


def test_export_unknown_scan_id_is_404():
    with _running_server() as base:
        r = httpx.get(base + "/api/export/deadbeef/json", timeout=5)
    assert r.status_code == 404
    assert "scan_id" in r.json()["error"]


def test_scan_cache_is_bounded(monkeypatch):
    # the LRU must not grow without bound as scans accumulate
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    server._SCANS.clear()
    with _running_server() as base:
        for _ in range(server._SCANS_MAX + 5):
            httpx.post(base + "/api/scan", json={"target": "h"}, timeout=5)
    assert len(server._SCANS) <= server._SCANS_MAX
