"""Stop / pause wiring through the engine (no network):
  * servicescan.orchestrator.run honours a ScanControl -- a stop returns the
    partial result and emits a final {phase:"stopped"} tick, cleanly;
  * webrecon.crawler.Crawler honours it in its BFS worker loop -- a stop ends
    the crawl with the partial result (like the time budget), a pause holds the
    loop until resumed.
"""
import asyncio

from servicescan import orchestrator, nmap_engine, fingerprint, cve
from servicescan.config import ScanConfig
from servicescan.models import Host, Service
from webrecon.config import Config
from webrecon.control import ScanControl
from webrecon.crawler import Crawler


# --- orchestrator ----------------------------------------------------------
class _FakeHTTP:
    def __init__(self, *a, **k):
        pass

    async def close(self):
        pass


def _stub_engine(monkeypatch, host):
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


def test_orchestrator_stop_returns_partial_and_emits_stopped(monkeypatch):
    host = Host(target="10.0.0.5", ip="10.0.0.5",
                services=[Service(port=445, proto="tcp", state="open",
                                  name="microsoft-ds")])
    _stub_engine(monkeypatch, host)
    control = ScanControl()
    control.stop()                       # stop before the host loop body

    events = []
    result = asyncio.run(orchestrator.run(
        ScanConfig(target="10.0.0.5", targets=["10.0.0.5"]),
        on_event=events.append, control=control))

    types = [e["type"] for e in events]
    phases = [e.get("phase") for e in events if e["type"] == "phase"]
    assert "stopped" in phases           # the stopped tick fired
    assert "host" not in types           # the stopped host never completed
    assert result.hosts                  # partial result still returned (no crash)


def test_orchestrator_no_control_is_unaffected(monkeypatch):
    host = Host(target="10.0.0.5", ip="10.0.0.5",
                services=[Service(port=445, proto="tcp", state="open",
                                  name="microsoft-ds")])
    _stub_engine(monkeypatch, host)
    events = []
    asyncio.run(orchestrator.run(
        ScanConfig(target="10.0.0.5", targets=["10.0.0.5"]),
        on_event=events.append))         # control defaults to None
    types = [e["type"] for e in events]
    assert "host" in types and "stopped" not in [e.get("phase") for e in events]


# --- crawler ---------------------------------------------------------------
class _Resp:
    def __init__(self, url, html):
        self.url = url; self.status = 200; self.final_url = url
        self.headers = {"content-type": "text/html"}; self.text = html
        self.content_type = "text/html"; self.length = len(html)
        self.ok = True; self.error = None


class _FrontierHTTP:
    """Each page links to 4 brand-new in-scope URLs, so the crawl never drains
    on its own -- only max_pages / a stop / the budget can end it."""
    def __init__(self):
        self._n = 0

    async def fetch(self, url, *a, **k):
        links = []
        for _ in range(4):
            self._n += 1
            links.append(f'<a href="http://x/p{self._n}">p{self._n}</a>')
        return _Resp(url, "<html>" + "".join(links) + "</html>")


def _crawl_cfg(**kw):
    c = Config(target="http://x/", render=False, same_scope_only=True,
               include_subdomains=True, do_secrets=False, do_js_extract=False,
               concurrency=1, max_pages=30, depth=50, time_budget=None)
    c.scope_hosts = {"x"}
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_crawler_stop_ends_with_partial_result():
    control = ScanControl()
    control.stop()                       # pre-stopped: worker returns at once
    cr = Crawler(_crawl_cfg(), _FrontierHTTP(), control=control)
    result = asyncio.run(asyncio.wait_for(cr.run(["http://x/"]), timeout=10))
    assert len(result.pages) == 0        # nothing crawled, but no crash/hang


def test_crawler_pause_holds_then_resumes():
    async def go():
        control = ScanControl()
        control.pause()
        cr = Crawler(_crawl_cfg(max_pages=20), _FrontierHTTP(), control=control)
        t = asyncio.ensure_future(cr.run(["http://x/"]))
        await asyncio.sleep(0.1)
        assert not t.done()              # held while paused
        assert len(cr.result.pages) == 0
        control.resume()
        result = await t                 # resumes and finishes
        assert len(result.pages) == cr.cfg.max_pages
    asyncio.run(asyncio.wait_for(go(), timeout=10))
