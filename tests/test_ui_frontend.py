"""webrecon_ui.server: static page + /api/alert-ids glue for the frontend.

The page itself is vanilla HTML/JS (no build step); these tests only assert the
server serves it correctly, exposes the alert-id source of truth the page needs,
and refuses anything outside the tiny static allowlist (no path traversal).
"""
import threading
import contextlib

import httpx

from webrecon_ui import server
from servicescan import fingerprint


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


def test_root_serves_html_page():
    with _running_server() as base:
        r = httpx.get(base + "/", timeout=5)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "<title>webrecon-ui</title>" in body
    assert 'id="scan-form"' in body          # the page actually wires the form
    assert "/api/scan" in body               # ... and calls the scan endpoint


def test_index_html_path_also_served():
    with _running_server() as base:
        r = httpx.get(base + "/index.html", timeout=5)
    assert r.status_code == 200
    assert "<title>webrecon-ui</title>" in r.text


def test_alert_ids_endpoint_matches_engine():
    with _running_server() as base:
        r = httpx.get(base + "/api/alert-ids", timeout=5)
    assert r.status_code == 200
    ids = set(r.json()["alert_ids"])
    # the page colours exposure findings off this; it must equal the engine's set
    assert ids == set(fingerprint.EXPOSURE_ALERT_IDS)
    assert "smb-signing-not-required" in ids
    assert "snmp-unauth" in ids


def test_no_path_traversal_outside_allowlist():
    # only "/" and "/index.html" are served; everything else is a flat 404 with
    # no filesystem access, so traversal attempts cannot read server.py etc.
    with _running_server() as base:
        for path in ("/server.py", "/../server.py", "/..%2fserver.py",
                     "/static/index.html", "/static/../server.py"):
            r = httpx.get(base + path, timeout=5)
            assert r.status_code == 404, path


def test_page_wires_greyed_download_during_scan():
    # exports work only on the completed/cached scan, so the download panel is
    # shown greyed+disabled during a scan (not hidden) with a hint, and enabled
    # on completion -- so the operator doesn't click a dead/absent button.
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert "setDownloadsState" in body
    assert "available when the scan finishes" in body
    assert "#downloads.pending" in body              # the greyed style
    assert 'setDownloadsState("pending")' in body    # entered at scan start
    assert 'setDownloadsState(scanId ? "ready" : "hidden")' in body
