"""servicescan --render wiring (browser-free: RootRenderer is faked)."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def test_merge_render_hits_dedup_and_version_fill():
    svc = Service(port=443, name="https", state="open")
    svc.aux.append(["Angular", ""])            # seen earlier without a version
    fp._merge_render_hits(svc, [["Angular", "17.1.2"], ["Ember.js", "3.28.0"],
                                ["Kubernetes Dashboard", ""]])
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux["Angular"] == "17.1.2"          # version filled, not duplicated
    assert len([p for p in svc.aux if p[0] == "Angular"]) == 1
    assert aux["Ember.js"] == "3.28.0"
    assert "Kubernetes Dashboard" in aux
    assert "render" in svc.sources
    assert any(s["id"] == "render-tech" for s in svc.scripts)


def test_merge_render_hits_empty_is_noop():
    svc = Service(port=80, name="http", state="open")
    fp._merge_render_hits(svc, [])
    assert svc.aux == [] and svc.scripts == [] and "render" not in svc.sources


class _FakeRenderer:
    """Stands in for webrecon.render.RootRenderer: returns canned rendered data
    so the wiring can be tested without a browser."""
    def __init__(self, page_by_port):
        self._by_port = page_by_port

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    @property
    def available(self):
        return True

    async def eval(self, url, js_vars, dom_specs):
        port = int(url.rsplit(":", 1)[1].rstrip("/"))
        return self._by_port.get(port)


def _run_with_fake(services, page_by_port, monkeypatch):
    import webrecon.render as render_mod
    monkeypatch.setattr(render_mod, "RootRenderer",
                        lambda *a, **k: _FakeRenderer(page_by_port))
    cfg = ScanConfig(target="x", render=True, timeout=5.0)
    asyncio.run(fp.run_render_catalog(cfg, "10.0.0.1", services))


def test_run_render_catalog_merges_versioned_app(monkeypatch):
    svc = Service(port=8443, name="https", state="open")
    page = {"status": 200, "headers": {}, "html": "",
            "js_globals": {"Ember": "", "Ember.VERSION": "3.28.0"},
            "dom_eval": {}}
    _run_with_fake([svc], {8443: page}, monkeypatch)
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Ember.js") == "3.28.0"


def test_run_render_catalog_skips_non_web(monkeypatch):
    svc = Service(port=22, name="ssh", state="open")
    _run_with_fake([svc], {22: {"status": 200, "headers": {}, "html": "",
                                "js_globals": {"Ember": ""}, "dom_eval": {}}},
                   monkeypatch)
    assert svc.aux == []                        # ssh is not a web service
