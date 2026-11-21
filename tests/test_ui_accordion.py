"""webrecon_ui: collapsible per-service rows in the results table.

Each service renders as one summary row (compact CVE/script/web chips); its full
scripts/CVEs/web detail is revealed on click. Exposure-ALERT services open by
default. The page is vanilla HTML/JS with no build step, so -- as with the other
frontend tests -- we assert the served page carries the accordion machinery and
the server still serves it correctly. No scan touches the network.
"""
import threading
import contextlib

import httpx

from webrecon_ui import server


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


def _page():
    with _running_server() as base:
        r = httpx.get(base + "/", timeout=5)
    assert r.status_code == 200
    return r.text


def test_page_has_collapsible_detail_markup():
    body = _page()
    # detail is hidden by default and shown only when the row is open
    assert ".detail { display:none; }" in body
    assert "tr.svc.open .detail { display:block; }" in body
    assert 'el("div", "detail")' in body        # detail container is built


def test_page_has_toggle_state_machine():
    body = _page()
    # explicit expand/collapse sets, keyed per host:port, survive re-renders
    assert "const EXPANDED = new Set();" in body
    assert "const COLLAPSED = new Set();" in body
    assert "function toggleSvc(" in body
    assert "function svcIsOpen(" in body
    # clicking a row toggles, but CVE links still work
    assert 'if (e.target.closest("a")) return;' in body


def test_alerts_open_by_default():
    body = _page()
    # svcIsOpen falls back to hasAlert -> exposure alerts are expanded by default
    assert "return hasAlert;" in body
    assert "const hasAlert = scripts.some((sc) => ALERT_IDS.has(sc.id));" in body


def test_summary_chips_rendered_and_state_reset_per_scan():
    body = _page()
    assert 'el("div", "summary")' in body            # compact summary row
    assert "CVE${cves.length > 1" in body            # CVE count chip
    assert "renderService(svc, h.ip" in body         # host key threaded through
    assert "EXPANDED.clear(); COLLAPSED.clear();" in body   # reset on new scan
