"""webrecon_ui.server: config mapping + HTTP API.

Exercises the stdlib server against a real ThreadingHTTPServer on an ephemeral
loopback port, with run_scan monkeypatched to a canned ScanResult so no scan
ever touches the network (same philosophy as the probe tests' mock servers).
"""
import threading
import contextlib

import httpx
import pytest

from webrecon_ui import server
from servicescan.config import ScanConfig
from servicescan.models import ScanResult, Host, Service


# --- build_config: allowlist + validation ---------------------------------
def test_build_config_splits_target_string():
    cfg = server.build_config({"target": "10.0.0.0/30 host2"})
    assert cfg.targets == ["10.0.0.0/30", "host2"]
    assert cfg.target == "10.0.0.0/30 host2"


def test_build_config_accepts_target_list():
    cfg = server.build_config({"target": ["a", " b ", ""]})
    assert cfg.targets == ["a", "b"]


def test_build_config_missing_target_is_bad_request():
    with pytest.raises(server.BadRequest):
        server.build_config({"ports": "80"})
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "   "})


def test_build_config_maps_allowlisted_fields_with_coercion():
    cfg = server.build_config({
        "target": "h", "ports": "1-1000", "use_nmap": "false",
        "udp": True, "fp_all": "yes", "min_cvss": "7.5",
        "top_ports": "100", "concurrency": "20", "timeout": "4",
    })
    assert cfg.ports == "1-1000"
    assert cfg.use_nmap is False
    assert cfg.udp is True
    assert cfg.fp_all is True
    assert cfg.min_cvss == 7.5
    assert cfg.top_ports == 100
    assert cfg.concurrency == 20
    assert cfg.timeout == 4.0


def test_build_config_ignores_non_allowlisted_keys():
    # nmap_path / nmap_args / outdir (host-filesystem / subprocess-path knobs)
    # must not be reachable from the web.
    cfg = server.build_config({
        "target": "h", "nmap_path": "/evil/nmap", "outdir": "/tmp/x",
        "nmap_args": ["--script", "x"],
    })
    assert cfg.nmap_path == ScanConfig().nmap_path   # unchanged default
    assert cfg.nmap_args == []
    assert cfg.outdir == ScanConfig().outdir


def test_build_config_maps_scan_knobs():
    # scan semantics that were previously CLI-only: rate / render / realm / web chain
    cfg = server.build_config({
        "target": "h", "scan_rate": "5000", "render": "true",
        "realm": "CORP.LOCAL", "web": "yes", "web_render": "1",
        "web_depth": "3", "web_max_pages": "200",
    })
    assert cfg.scan_rate == 5000
    assert cfg.render is True
    assert cfg.realm == "CORP.LOCAL"
    assert cfg.web is True
    assert cfg.web_render is True
    assert cfg.web_depth == 3
    assert cfg.web_max_pages == 200


def test_build_config_realm_blank_is_none_and_overlong_rejected():
    assert server.build_config({"target": "h", "realm": "  "}).realm is None
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "h", "realm": "A" * 300})


def test_build_config_web_depth_floor_is_one():
    cfg = server.build_config({"target": "h", "web": True, "web_depth": "0"})
    assert cfg.web_depth == 1


def test_build_config_bad_number_is_bad_request():
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "h", "min_cvss": "high"})


# --- live HTTP API --------------------------------------------------------
@contextlib.contextmanager
def _running_server():
    httpd = server.make_server("127.0.0.1", 0)       # port 0 = ephemeral
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        host, port = httpd.server_address
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


def _canned_result():
    svc = Service(port=445, proto="tcp", state="open", name="microsoft-ds")
    svc.scripts.append({"id": "smb-signing-not-required", "output": "relay risk"})
    host = Host(target="10.0.0.5", ip="10.0.0.5", services=[svc])
    return ScanResult(target="10.0.0.5", hosts=[host], nmap_used=False)


def test_health(monkeypatch):
    with _running_server() as base:
        r = httpx.get(base + "/api/health", timeout=5)
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "webrecon-ui"}


def test_scan_returns_result_dict(monkeypatch):
    captured = {}

    def fake(cfg):
        captured["cfg"] = cfg
        return _canned_result()

    monkeypatch.setattr(server, "run_scan", fake)
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"target": "10.0.0.5", "fp_all": True},
                       timeout=5)
    assert r.status_code == 200
    body = r.json()
    assert body["target"] == "10.0.0.5"
    assert body["hosts"][0]["services"][0]["port"] == 445
    # request field flowed into the ScanConfig handed to the engine
    assert captured["cfg"].fp_all is True
    assert captured["cfg"].targets == ["10.0.0.5"]


def test_scan_sarif_endpoint(monkeypatch):
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    with _running_server() as base:
        r = httpx.post(base + "/api/scan.sarif", json={"target": "10.0.0.5"}, timeout=5)
    assert r.status_code == 200
    doc = r.json()
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "servicescan"


def test_scan_missing_target_is_400(monkeypatch):
    monkeypatch.setattr(server, "run_scan", lambda cfg: _canned_result())
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"ports": "80"}, timeout=5)
    assert r.status_code == 400
    assert "target" in r.json()["error"]


def test_scan_bad_json_is_400():
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", content=b"{not json",
                       headers={"Content-Type": "application/json"}, timeout=5)
    assert r.status_code == 400


def test_scan_engine_error_is_500(monkeypatch):
    def boom(cfg):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(server, "run_scan", boom)
    with _running_server() as base:
        r = httpx.post(base + "/api/scan", json={"target": "h"}, timeout=5)
    assert r.status_code == 500
    assert "engine exploded" in r.json()["error"]


def test_unknown_route_is_404():
    with _running_server() as base:
        r = httpx.get(base + "/nope", timeout=5)
    assert r.status_code == 404
