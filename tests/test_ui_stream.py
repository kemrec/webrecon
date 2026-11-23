"""webrecon_ui.server: GET /api/scan/stream (Server-Sent Events live scan).

run_scan is monkeypatched to a fake that fires on_event milestones and returns a
canned ScanResult, so nothing touches the network. The server appends the final
'done' event (with the scan_id) itself; we read the SSE frames over httpx.
"""
import json
import threading
import contextlib

import httpx
import pytest

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


def _host_dict():
    svc = Service(port=445, proto="tcp", state="open", name="microsoft-ds", product="SMB")
    svc.sources = ["exposure"]
    return Host(target="10.0.0.5", ip="10.0.0.5", services=[svc]).to_dict()


def _read_stream(base, qs, timeout=10):
    events = []
    with httpx.stream("GET", base + "/api/scan/stream?" + qs, timeout=timeout) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                events.append(ev)
                if ev.get("type") in ("done", "error"):
                    break
    return events


def test_stream_emits_start_host_done(monkeypatch):
    captured = {}

    def fake(cfg, on_event=None, control=None):
        captured["cfg"] = cfg
        if on_event:
            on_event({"type": "start", "nhosts": 1})
            on_event({"type": "host", "host": _host_dict()})
        return ScanResult(target=cfg.target, hosts=[], nmap_used=True)

    monkeypatch.setattr(server, "run_scan", fake)
    with _running_server() as base:
        events = _read_stream(base, "target=10.0.0.5&fp_all=true")

    types = [e["type"] for e in events]
    # the server hands out the scan id up front (for the pause/stop controls)
    # before the scan's own milestones.
    assert types == ["accepted", "start", "host", "done"]
    assert events[0]["scan_id"]
    assert events[1]["nhosts"] == 1
    assert events[2]["host"]["services"][0]["port"] == 445
    assert events[-1]["scan_id"] == events[0]["scan_id"]   # same id at done
    assert events[-1]["nmap_used"] is True
    # query-string config flowed through the same allowlist as POST
    assert captured["cfg"].fp_all is True
    assert captured["cfg"].targets == ["10.0.0.5"]


def test_stream_done_scan_id_is_exportable(monkeypatch):
    def fake(cfg, on_event=None, control=None):
        if on_event:
            on_event({"type": "host", "host": _host_dict()})
        svc = Service(port=445, proto="tcp", state="open", name="microsoft-ds")
        h = Host(target="10.0.0.5", ip="10.0.0.5", services=[svc])
        return ScanResult(target="10.0.0.5", hosts=[h], nmap_used=False)

    monkeypatch.setattr(server, "run_scan", fake)
    with _running_server() as base:
        events = _read_stream(base, "target=10.0.0.5")
        sid = events[-1]["scan_id"]
        # the id the stream reported must drive the export endpoints
        r = httpx.get(f"{base}/api/export/{sid}/services-csv", timeout=5)
    assert r.status_code == 200
    assert "445" in r.text


def test_stream_scan_error_emits_error_event(monkeypatch):
    def boom(cfg, on_event=None, control=None):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(server, "run_scan", boom)
    with _running_server() as base:
        events = _read_stream(base, "target=h")
    assert events[-1]["type"] == "error"
    assert "engine exploded" in events[-1]["error"]


def test_stream_missing_target_is_400():
    # build_config rejects before streaming starts
    with _running_server() as base:
        r = httpx.get(base + "/api/scan/stream?ports=80", timeout=5)
    assert r.status_code == 400
