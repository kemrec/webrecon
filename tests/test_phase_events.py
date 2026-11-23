"""Live high-level progress ticks: orchestrator.run emits {type:"phase"} events
at each sub-phase boundary so the web UI can show what the scan is doing during
the long silent stretches between the coarse start/host milestones.

Three layers are guarded:
  1. orchestrator.run emits the phase ticks in the right order (the real
     placement guard) -- every engine call is monkeypatched to a no-op, so
     nothing touches nmap or the network;
  2. the SSE endpoint relays phase ticks to the wire verbatim;
  3. the static page actually wires the live-phase panel that renders them.
"""
import asyncio
import contextlib
import json
import threading

import httpx

from servicescan import orchestrator, nmap_engine, fingerprint, cve
from servicescan import chain as chain_mod
from servicescan.config import ScanConfig
from servicescan.models import ScanResult, Host, Service
from webrecon_ui import server


def _host():
    svc = Service(port=445, proto="tcp", state="open", name="microsoft-ds")
    return Host(target="10.0.0.5", ip="10.0.0.5", services=[svc])


class _FakeHTTP:
    def __init__(self, *a, **k):
        pass

    async def close(self):
        pass


def _stub_engine(monkeypatch, host):
    """Replace every awaited engine step with a no-op so run() only exercises
    its own control flow + emits (no nmap, no sockets, no CVE lookups)."""
    async def _anoop(*a, **k):
        return None

    async def _fake_nmap(cfg):
        return [host], ""

    monkeypatch.setattr(nmap_engine, "nmap_available", lambda path: True)
    monkeypatch.setattr(nmap_engine, "run_nmap", _fake_nmap)
    for fn in ("run_fingerprint", "run_exposure_checks",
               "run_discovery_probes", "run_render_catalog"):
        monkeypatch.setattr(fingerprint, fn, _anoop)
    monkeypatch.setattr(cve, "correlate", _anoop)
    monkeypatch.setattr(cve, "refine_ftp_alpaca", _anoop)
    monkeypatch.setattr(orchestrator, "HTTPClient", _FakeHTTP)


def _run(cfg):
    events = []
    asyncio.run(orchestrator.run(cfg, on_event=events.append))
    return events


def test_orchestrator_emits_phase_ticks_in_order(monkeypatch):
    host = _host()
    _stub_engine(monkeypatch, host)
    cfg = ScanConfig(target="10.0.0.5", targets=["10.0.0.5"])  # fp+cve default on

    events = _run(cfg)

    # (type, phase) skeleton -- render/web are off, so neither appears.
    skeleton = [(e["type"], e.get("phase")) for e in events]
    assert skeleton == [
        ("phase", "nmap"),
        ("start", None),
        ("phase", "fingerprint"),
        ("phase", "exposure"),
        ("phase", "cve"),
        ("host", None),
    ]
    # per-host phases carry the host label; nmap (host-agnostic) does not.
    by_phase = {e["phase"]: e for e in events if e["type"] == "phase"}
    assert by_phase["fingerprint"]["host"] == "10.0.0.5"
    assert by_phase["cve"]["host"] == "10.0.0.5"
    assert "host" not in by_phase["nmap"]


def test_render_and_web_phases_only_when_enabled(monkeypatch):
    host = _host()
    _stub_engine(monkeypatch, host)

    async def _achain(cfg, result, control=None):
        return None
    monkeypatch.setattr(chain_mod, "run_web_chain", _achain)

    cfg = ScanConfig(target="10.0.0.5", targets=["10.0.0.5"],
                     render=True, web=True)
    phases = [e["phase"] for e in _run(cfg) if e["type"] == "phase"]

    assert phases == ["nmap", "fingerprint", "exposure", "render", "cve", "web"]


def test_no_phase_when_steps_disabled(monkeypatch):
    host = _host()
    _stub_engine(monkeypatch, host)
    cfg = ScanConfig(target="10.0.0.5", targets=["10.0.0.5"],
                     use_nmap=False, fingerprint=False, cve=False)

    phases = [e["phase"] for e in _run(cfg) if e["type"] == "phase"]
    # no nmap (disabled), no fingerprint/cve (disabled) -> zero ticks
    assert phases == []


# --- SSE relay ------------------------------------------------------------

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


def _read_stream(base, qs, timeout=10):
    events = []
    with httpx.stream("GET", base + "/api/scan/stream?" + qs,
                      timeout=timeout) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                events.append(ev)
                if ev.get("type") in ("done", "error"):
                    break
    return events


def test_sse_relays_phase_ticks_verbatim(monkeypatch):
    def fake(cfg, on_event=None, control=None):
        if on_event:
            on_event({"type": "phase", "phase": "nmap"})
            on_event({"type": "start", "nhosts": 1})
            on_event({"type": "phase", "phase": "cve", "host": "10.0.0.5"})
            on_event({"type": "host", "host": _host().to_dict()})
        return ScanResult(target=cfg.target, hosts=[], nmap_used=True)

    monkeypatch.setattr(server, "run_scan", fake)
    with _running_server() as base:
        events = _read_stream(base, "target=10.0.0.5")

    types = [e["type"] for e in events]
    # 'accepted' (scan id up front) precedes the scan's own ticks
    assert types == ["accepted", "phase", "start", "phase", "host", "done"]
    assert events[1]["phase"] == "nmap"
    assert events[3]["phase"] == "cve" and events[3]["host"] == "10.0.0.5"


# --- frontend wiring ------------------------------------------------------

def test_page_wires_live_phase_panel():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    # the panel the ticks render into
    assert 'id="progress"' in body
    assert 'id="live-history"' in body
    assert 'id="live-text"' in body
    # the stream branch + the label table that turns a phase into a human line
    assert 'msg.type === "phase"' in body
    assert "PHASE_LABELS" in body
    assert "correlating CVEs" in body
