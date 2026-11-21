"""webrecon_ui.server: /api/export/<scan_id>/all -> every output as one zip.

report.write_all drops the whole output tree into a temp dir in one pass; the
"all" export zips that tree verbatim, so the archive is a superset of the per-
format downloads. run_scan is monkeypatched so nothing touches the network.
"""
import io
import re
import threading
import contextlib
import zipfile

import httpx

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


def _canned_result(target="10.0.0.5"):
    web = Service(port=443, proto="tcp", state="open", name="https", product="nginx",
                  version="1.18.0")
    web.sources = ["nmap"]
    web.cves.append(CVE(id="CVE-2021-23017", source="nvd", cvss=9.8, severity="CRITICAL",
                        summary="resolver off-by-one", url="https://x/CVE-2021-23017"))
    smb = Service(port=445, proto="tcp", state="open", name="microsoft-ds", product="SMB")
    smb.sources = ["exposure"]
    smb.scripts.append({"id": "smb-signing-not-required", "output": "relay risk"})
    host = Host(target=target, ip=target, services=[web, smb])
    return ScanResult(target=target, hosts=[host], nmap_used=True)


@contextlib.contextmanager
def _scanned(monkeypatch, target="10.0.0.5"):
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result(target))
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"target": target}, timeout=5)
        assert r.status_code == 200
        yield base, r.json()["scan_id"]


# --- the zip endpoint ------------------------------------------------------
def test_export_all_is_a_zip_with_timestamped_name(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        r = httpx.get(f"{base}/api/export/{sid}/all", timeout=10)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    cd = r.headers.get("content-disposition", "")
    m = re.search(r'filename="([^"]+)"', cd)
    assert m, cd
    # <target-slug>-<YYYYMMDD-HHMMSS>.zip
    assert re.fullmatch(r"10\.0\.0\.5-\d{8}-\d{6}\.zip", m.group(1)), m.group(1)


def test_export_all_zip_contains_every_format(monkeypatch):
    with _scanned(monkeypatch) as (base, sid):
        r = httpx.get(f"{base}/api/export/{sid}/all", timeout=10)
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    # a superset of the single-file exports (same writers, one pass)
    for expected in ("scan.json", "scan.sarif", "services.csv", "cves.csv",
                     "report.html", "services.txt"):
        assert expected in names, (expected, names)
    # the zip's own members are intact and non-empty
    assert zf.testzip() is None
    assert b"10.0.0.5" in zf.read("scan.json")


def test_export_all_unknown_scan_id_is_404():
    with _running_server() as base:
        r = httpx.get(base + "/api/export/deadbeef/all", timeout=5)
    assert r.status_code == 404
    assert "scan_id" in r.json()["error"]


# --- the filename slug -----------------------------------------------------
def test_safe_slug_sanitizes_target_specs():
    # spaces / slashes (CIDR, multi-host) collapse to a safe stem
    assert server._safe_slug("10.0.0.0/24 host2") == "10.0.0.0_24_host2"
    assert server._safe_slug("  ") == "scan"              # empty -> fallback
    assert server._safe_slug("a" * 200) == "a" * 60       # length-capped
    assert "/" not in server._safe_slug("../../etc/passwd")
