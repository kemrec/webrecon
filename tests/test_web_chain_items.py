"""The --web chain echoes bounded SAMPLES of the real crawl findings onto
svc.web (endpoint/param/secret items), so the UI can expand its web summary
into actual items like the service-row accordion -- not just counts. The full,
unbounded set still only lives in the saved output tree.

web_orch.run is monkeypatched to a canned crawl result (no network); the web
service is plain HTTP so no TLS cert grab fires either.
"""
import asyncio
import contextlib
import threading

import httpx

from servicescan import chain
from servicescan.config import ScanConfig
from servicescan.models import ScanResult, Host, Service
from webrecon import orchestrator as web_orch, report as web_report
from webrecon_ui import server


def _canned(n_eps=80, n_params=70, n_secrets=3):
    return {
        "pages": {f"/p{i}": {} for i in range(5)},
        "urls": [f"http://x/u{i}" for i in range(120)],
        "endpoints": [f"/api/e{i}" for i in range(n_eps)],
        "params": {f"/api/e{i}": [f"p{i}a", f"p{i}b"] for i in range(n_params)},
        "secrets": [{"type": "AWS Access Key ID", "severity": "high",
                     "match_preview": "AKIAEXAMPLE1234567",
                     "source": "http://x/app.js", "context": "...", "line": 12}
                    for _ in range(n_secrets)],
        "vhosts": ["admin.internal"],
        "subdomains": [],
        "tech": ["nginx", "React"],
        "forms": [],
    }


def test_svc_web_carries_bounded_item_samples(monkeypatch, tmp_path):
    async def fake_run(wcfg):
        return _canned()
    monkeypatch.setattr(web_orch, "run", fake_run)
    monkeypatch.setattr(web_report, "write_all", lambda outdir, data: None)

    svc = Service(port=80, proto="tcp", state="open", name="http")
    host = Host(target="10.0.0.9", ip="10.0.0.9", services=[svc])
    result = ScanResult(target="10.0.0.9", hosts=[host])
    cfg = ScanConfig(target="10.0.0.9", web=True, outdir=str(tmp_path))

    asyncio.run(chain.run_web_chain(cfg, result))

    w = svc.web
    # counts stay authoritative (full totals)
    assert w["endpoints"] == 80 and w["params"] == 70 and w["secrets"] == 3
    # samples are capped at _WEB_SAMPLE and carry the REAL items
    assert len(w["endpoint_list"]) == chain._WEB_SAMPLE == 60
    assert w["endpoint_list"][0] == "/api/e0"
    assert len(w["param_list"]) == 60
    assert w["param_list"][0] == {"ep": "/api/e0", "names": ["p0a", "p0b"]}
    # all 3 secrets fit under the cap; values are NOT redacted (operator tool)
    assert len(w["secret_list"]) == 3
    assert w["secret_list"][0]["type"] == "AWS Access Key ID"
    assert w["secret_list"][0]["match_preview"] == "AKIAEXAMPLE1234567"


def test_secret_sample_is_bounded(monkeypatch, tmp_path):
    async def fake_run(wcfg):
        return _canned(n_eps=1, n_params=0, n_secrets=200)
    monkeypatch.setattr(web_orch, "run", fake_run)
    monkeypatch.setattr(web_report, "write_all", lambda outdir, data: None)

    svc = Service(port=80, proto="tcp", state="open", name="http")
    host = Host(target="h", ip="10.0.0.9", services=[svc])
    cfg = ScanConfig(target="h", web=True, outdir=str(tmp_path))
    asyncio.run(chain.run_web_chain(cfg, ScanResult(target="h", hosts=[host])))

    assert svc.web["secrets"] == 200                      # count is the truth
    assert len(svc.web["secret_list"]) == chain._WEB_SAMPLE  # sample is capped


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


def test_page_wires_expandable_web_detail():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    # the expandable web body + the item arrays it renders
    assert "web-body" in body
    assert "secret_list" in body
    assert "endpoint_list" in body
    assert "param_list" in body
    assert "web-sec-h" in body
    # clicking the web header must not collapse the parent service row
    assert "stopPropagation" in body
