"""webrecon_ui: POST /api/reveal -> open a saved scan's folder in the file manager.

Localhost-only convenience: the server runs xdg-open/open/explorer on the dir it
remembered for a scan_id (never a path from the request). The real opener is
monkeypatched so no window spawns under CI; the tests focus on the CSRF guard and
the path lookup. run_scan is monkeypatched so nothing touches the network.
"""
import os
import shutil
import threading
import contextlib

import httpx

from webrecon_ui import server
from servicescan.models import ScanResult, Host, Service


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
    svc = Service(port=80, proto="tcp", state="open", name="http", product="nginx")
    svc.sources = ["nmap"]
    return ScanResult(target=target, hosts=[Host(target=target, ip=target, services=[svc])],
                      nmap_used=True)


_HDR = {"X-Requested-With": "webrecon-ui"}


@contextlib.contextmanager
def _saved(monkeypatch, tmp_path):
    """A running server with one save-to-disk scan already done; yields (base, sid, opener_calls)."""
    monkeypatch.setattr(server, "_SAVE_BASE", str(tmp_path))
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    calls = []
    monkeypatch.setattr(server, "_open_in_file_manager", lambda p: calls.append(p))
    with _running_server() as base:
        r = httpx.post(base + "/api/scan",
                       json={"target": "10.0.0.5", "save_to_disk": True}, timeout=10)
        assert r.status_code == 200
        yield base, r.json()["scan_id"], r.json()["outdir"], calls


def test_reveal_opens_the_saved_dir(monkeypatch, tmp_path):
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        r = httpx.post(base + "/api/reveal", json={"scan_id": sid}, headers=_HDR, timeout=5)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert calls == [outdir]           # opener invoked with the remembered path


def test_reveal_requires_csrf_header(monkeypatch, tmp_path):
    # no X-Requested-With -> a drive-by cross-site POST would look like this
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        r = httpx.post(base + "/api/reveal", json={"scan_id": sid}, timeout=5)
    assert r.status_code == 403
    assert calls == []                 # opener never ran


def test_reveal_rejects_foreign_origin(monkeypatch, tmp_path):
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        r = httpx.post(base + "/api/reveal", json={"scan_id": sid},
                       headers={**_HDR, "Origin": "http://evil.example"}, timeout=5)
    assert r.status_code == 403
    assert calls == []


def test_reveal_accepts_loopback_origin(monkeypatch, tmp_path):
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        r = httpx.post(base + "/api/reveal", json={"scan_id": sid},
                       headers={**_HDR, "Origin": "http://localhost:8787"}, timeout=5)
    assert r.status_code == 200
    assert calls == [outdir]


def test_reveal_unknown_scan_id_is_404(monkeypatch, tmp_path):
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        r = httpx.post(base + "/api/reveal", json={"scan_id": "deadbeef"},
                       headers=_HDR, timeout=5)
    assert r.status_code == 404
    assert calls == []


def test_reveal_vanished_dir_is_409(monkeypatch, tmp_path):
    with _saved(monkeypatch, tmp_path) as (base, sid, outdir, calls):
        shutil.rmtree(outdir)          # directory removed after the scan
        r = httpx.post(base + "/api/reveal", json={"scan_id": sid}, headers=_HDR, timeout=5)
    assert r.status_code == 409
    assert calls == []


def test_page_has_open_folder_button():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="open-folder"' in body
    assert "/api/reveal" in body
    assert '"X-Requested-With": "webrecon-ui"' in body
