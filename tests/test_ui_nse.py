"""webrecon_ui: NSE toggle + nse_scripts selection wired into the console.

`nse` turns on nmap's --script run; `nse_scripts` picks which scripts/categories
run. The value becomes a single argv token after "--script" (no shell), so these
tests only check the allowlist coercion and that the page exposes the controls.
No scan touches the network.
"""
import threading
import contextlib

import httpx
import pytest

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


# --- build_config: nse + nse_scripts --------------------------------------
def test_nse_toggle_and_scripts_map():
    cfg = server.build_config({"target": "h", "nse": "true",
                               "nse_scripts": "http-vuln-cve2017-5638,smb-vuln*"})
    assert cfg.nse is True
    assert cfg.nse_scripts == "http-vuln-cve2017-5638,smb-vuln*"


def test_nse_scripts_default_when_blank():
    # empty -> the engine default category, matching ScanConfig's "vuln"
    assert server.build_config({"target": "h", "nse_scripts": "  "}).nse_scripts == "vuln"
    assert ScanConfig().nse_scripts == "vuln"


def test_nse_scripts_rejects_leading_dash():
    # defence in depth: a value that looks like a flag is refused (it could never
    # actually inject one -- it's a single argv token -- but we reject it anyway)
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "h", "nse_scripts": "-sS"})


def test_nse_scripts_rejects_overlong():
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "h", "nse_scripts": "a" * 300})


def test_nse_scripts_default_off():
    # without any nse keys, defaults are preserved (NSE off, default category)
    cfg = server.build_config({"target": "h"})
    assert cfg.nse is False
    assert cfg.nse_scripts == "vuln"


# --- frontend exposes the controls ----------------------------------------
def test_page_has_nse_controls():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="nse"' in body            # the NSE-on checkbox
    assert 'id="nse_scripts"' in body    # the script-selection input
    assert 'p.set("nse"' in body         # ... and the form actually sends it
