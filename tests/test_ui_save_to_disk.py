"""webrecon_ui: optional "save to disk" -- persist a scan's full output tree.

With save_to_disk, the server writes report.write_all into a server-chosen dir
(_SAVE_BASE/<target-slug>-<timestamp>/) and returns its absolute path; the web
never supplies the path. run_scan is monkeypatched so nothing touches the
network, and _SAVE_BASE is pointed at a tmp dir so the test writes nowhere else.
"""
import os
import re
import threading
import contextlib

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
                        summary="off-by-one", url="https://x/CVE-2021-23017"))
    host = Host(target=target, ip=target, services=[web])
    return ScanResult(target=target, hosts=[host], nmap_used=True)


def test_save_to_disk_writes_tree_and_returns_abspath(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_SAVE_BASE", str(tmp_path))
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    with _running_server() as base:
        r = httpx.post(base + "/api/scan",
                       json={"target": "10.0.0.5", "save_to_disk": True}, timeout=10)
    assert r.status_code == 200
    body = r.json()
    outdir = body.get("outdir")
    assert outdir, body
    # the server chose a path UNDER our base, named <slug>-<timestamp>
    assert os.path.abspath(outdir).startswith(os.path.abspath(str(tmp_path)))
    assert re.fullmatch(r"10\.0\.0\.5-\d{8}-\d{6}", os.path.basename(outdir))
    # the full output tree really landed there
    assert os.path.isfile(os.path.join(outdir, "scan.json"))
    assert os.path.isfile(os.path.join(outdir, "report.html"))
    with open(os.path.join(outdir, "scan.json")) as fh:
        assert "10.0.0.5" in fh.read()


def test_no_save_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_SAVE_BASE", str(tmp_path))
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"target": "10.0.0.5"}, timeout=5)
    assert r.status_code == 200
    assert "outdir" not in r.json()
    assert list(tmp_path.iterdir()) == []       # nothing written to disk


def test_scan_dir_for_is_confined_and_timestamped(monkeypatch):
    monkeypatch.setattr(server, "_SAVE_BASE", "/base/scans")
    d = server.scan_dir_for("10.0.0.0/24 host2")
    # derived purely from base + sanitised slug + timestamp (no request path in it)
    assert d.startswith("/base/scans/")
    assert re.fullmatch(r"10\.0\.0\.0_24_host2-\d{8}-\d{6}", os.path.basename(d))


def test_stream_done_event_carries_outdir(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_SAVE_BASE", str(tmp_path))
    monkeypatch.setattr(server, "run_scan",
                        lambda cfg, on_event=None: _canned_result())
    seen = {}
    with _running_server() as base:
        with httpx.stream("GET", base + "/api/scan/stream",
                          params={"target": "10.0.0.5", "save_to_disk": "true"},
                          timeout=10) as resp:
            for line in resp.iter_lines():
                if line.startswith("data: ") and '"done"' in line:
                    import json as _j
                    seen = _j.loads(line[6:])
                    break
    assert seen.get("outdir")
    assert os.path.isfile(os.path.join(seen["outdir"], "scan.json"))


def test_page_has_save_to_disk_controls():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="save_to_disk"' in body
    assert 'id="saved-row"' in body
    assert 'id="copy-path"' in body
    assert 'p.set("save_to_disk"' in body
