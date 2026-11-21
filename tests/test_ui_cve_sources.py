"""webrecon_ui: CVE-source toggles (nvd/osv/epss/kev) + NVD API key in the console.

Each CVE feed can be turned off independently, and an optional NVD API key (which
only raises the NVD rate limit) can be supplied. These are scan *semantics*, not
host-filesystem/subprocess knobs, so they are allowlisted. No network access.
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


# --- build_config: source feeds -------------------------------------------
def test_cve_source_toggles_map():
    cfg = server.build_config({
        "target": "h", "nvd": "false", "osv": "true",
        "epss": "0", "kev": "1",
    })
    assert cfg.nvd is False
    assert cfg.osv is True
    assert cfg.epss is False
    assert cfg.kev is True


def test_cve_sources_default_on():
    # unspecified feeds keep ScanConfig's defaults (all on)
    cfg = server.build_config({"target": "h"})
    assert (cfg.nvd, cfg.osv, cfg.epss, cfg.kev) == (True, True, True, True)
    assert (ScanConfig().nvd, ScanConfig().osv) == (True, True)


# --- build_config: NVD API key --------------------------------------------
def test_nvd_api_key_maps():
    cfg = server.build_config({"target": "h", "nvd_api_key": "  deadBEEF-key  "})
    assert cfg.nvd_api_key == "deadBEEF-key"       # trimmed


def test_nvd_api_key_blank_is_none():
    assert server.build_config({"target": "h", "nvd_api_key": "   "}).nvd_api_key is None
    assert ScanConfig().nvd_api_key is None


def test_nvd_api_key_overlong_rejected():
    with pytest.raises(server.BadRequest):
        server.build_config({"target": "h", "nvd_api_key": "k" * 300})


# --- frontend exposes the controls ----------------------------------------
def test_page_has_cve_source_controls():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    for cid in ('id="nvd"', 'id="osv"', 'id="epss"', 'id="kev"', 'id="nvd_api_key"'):
        assert cid in body, cid
    assert 'p.set("nvd"' in body        # the form sends the feed toggles
