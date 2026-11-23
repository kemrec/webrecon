"""webrecon_ui: pause / resume / stop controls for a live streaming scan.

The stream hands out the scan id up front (an 'accepted' event) and registers a
ScanControl; POST /api/scan/<id>/{pause,resume,stop} signals it (same loopback
CSRF guard as /api/reveal). The scan honours the signal cooperatively. No
network: run_scan is monkeypatched.
"""
import contextlib
import json
import threading
import time

import httpx

from webrecon_ui import server
from webrecon.control import ScanControl
from servicescan.models import ScanResult


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


_SID = "0123456789abcdef0123456789abcdef"      # 32-hex, matches the route regex
_XRW = {"X-Requested-With": "webrecon-ui"}


# --- endpoint behaviour (control registered directly) ----------------------
def test_pause_resume_stop_signal_the_control():
    ctl = ScanControl()
    server._CONTROLS[_SID] = ctl
    try:
        with _running_server() as base:
            r = httpx.post(f"{base}/api/scan/{_SID}/pause", headers=_XRW, timeout=5)
            assert r.status_code == 200 and r.json()["state"] == "paused"
            assert ctl.paused is True

            r = httpx.post(f"{base}/api/scan/{_SID}/resume", headers=_XRW, timeout=5)
            assert r.status_code == 200 and r.json()["state"] == "running"
            assert ctl.paused is False

            r = httpx.post(f"{base}/api/scan/{_SID}/stop", headers=_XRW, timeout=5)
            assert r.status_code == 200 and r.json()["state"] == "stopped"
            assert ctl.stopped is True
    finally:
        server._CONTROLS.pop(_SID, None)


def test_control_requires_csrf_header():
    server._CONTROLS[_SID] = ScanControl()
    try:
        with _running_server() as base:
            # no X-Requested-With -> blocked
            r = httpx.post(f"{base}/api/scan/{_SID}/stop", timeout=5)
            assert r.status_code == 403
            # a foreign Origin -> blocked even with the header
            r = httpx.post(f"{base}/api/scan/{_SID}/stop",
                           headers={**_XRW, "Origin": "http://evil.example"}, timeout=5)
            assert r.status_code == 403
    finally:
        server._CONTROLS.pop(_SID, None)


def test_control_unknown_scan_is_404():
    with _running_server() as base:
        r = httpx.post(f"{base}/api/scan/{_SID}/stop", headers=_XRW, timeout=5)
    assert r.status_code == 404


# --- end-to-end: stop reaches a running streamed scan ----------------------
def test_stream_accepted_then_stop_ends_scan(monkeypatch):
    def fake(cfg, on_event=None, control=None):
        # a cooperative scan: emit start, then spin until stopped.
        if on_event:
            on_event({"type": "start", "nhosts": 1})
        for _ in range(1000):
            if control is not None and control.stopped:
                break
            time.sleep(0.01)
        return ScanResult(target=cfg.target, hosts=[], nmap_used=False)

    monkeypatch.setattr(server, "run_scan", fake)
    seen_sid = None
    done = None
    with _running_server() as base:
        with httpx.stream("GET", base + "/api/scan/stream?target=10.0.0.5",
                          timeout=15) as r:
            for line in r.iter_lines():
                if not line.startswith("data: "):
                    continue
                ev = json.loads(line[6:])
                if ev["type"] == "accepted":
                    seen_sid = ev["scan_id"]
                    pr = httpx.post(f"{base}/api/scan/{seen_sid}/stop",
                                    headers=_XRW, timeout=5)
                    assert pr.status_code == 200
                    assert pr.json()["state"] == "stopped"
                elif ev["type"] == "done":
                    done = ev
                    break
    assert seen_sid
    assert done is not None and done["stopped"] is True
    assert done["scan_id"] == seen_sid
    # the control handle is dropped once the scan finishes
    assert seen_sid not in server._CONTROLS


# --- page wiring -----------------------------------------------------------
def test_page_has_scan_control_buttons():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="pause-btn"' in body
    assert 'id="stop-btn"' in body
    assert 'addEventListener("click", togglePause)' in body
    assert 'addEventListener("click", stopScan)' in body
    # the controls address the run by the id handed out in the 'accepted' event
    assert '"/api/scan/" + controlId + "/" + action' in body
