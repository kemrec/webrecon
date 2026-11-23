"""webrecon_ui: --web-time-budget knob in the console.

A wall-clock cap (seconds) on each per-port web crawl. Scan semantics (never a
path/subprocess value), so it is allowlisted; blank / non-positive -> no limit,
matching the engine. No network access.
"""
import contextlib
import threading

import httpx

from webrecon_ui import server
from servicescan.config import ScanConfig


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


# --- build_config -----------------------------------------------------------
def test_web_time_budget_maps():
    cfg = server.build_config({"target": "h", "web": "true",
                               "web_time_budget": "120"})
    assert cfg.web_time_budget == 120.0


def test_web_time_budget_default_none():
    cfg = server.build_config({"target": "h"})
    assert cfg.web_time_budget is None
    assert ScanConfig().web_time_budget is None


def test_web_time_budget_blank_is_none():
    assert server.build_config(
        {"target": "h", "web_time_budget": ""}).web_time_budget is None


def test_web_time_budget_nonpositive_is_none():
    # a 0 / negative budget means "no limit" (a falsy budget = unlimited in the
    # engine), never an immediately-expired crawl.
    assert server.build_config(
        {"target": "h", "web_time_budget": "0"}).web_time_budget is None
    assert server.build_config(
        {"target": "h", "web_time_budget": "-5"}).web_time_budget is None


# --- page wiring ------------------------------------------------------------
def test_page_has_web_time_budget_control():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="web_time_budget"' in body
    assert 'p.set("web_time_budget"' in body
    # step="any" (not a fixed step) so a non-multiple value can't silently block
    # HTML5 constraint-validation submit.
    assert 'id="web_time_budget" min="1" step="any"' in body
