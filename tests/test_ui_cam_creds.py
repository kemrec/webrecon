"""webrecon_ui: camera default-credential toggle (cam_creds) in the console.

`cam_creds` governs the one active camera-recon step -- trying a tiny factory-
default credential list on a gated RTSP/ONVIF/vendor-CGI device. It defaults on
(as the engine does); unchecking it makes the run fully passive/read-only. Pure
allowlist coercion, no network access.
"""
import threading
import contextlib

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


# --- build_config: cam_creds ----------------------------------------------
def test_cam_creds_can_be_disabled():
    cfg = server.build_config({"target": "h", "cam_creds": "false"})
    assert cfg.cam_creds is False


def test_cam_creds_defaults_on():
    # unspecified -> ScanConfig default (the active default-cred step runs)
    assert server.build_config({"target": "h"}).cam_creds is True
    assert ScanConfig().cam_creds is True


def test_cam_creds_truthy_strings():
    assert server.build_config({"target": "h", "cam_creds": "on"}).cam_creds is True
    assert server.build_config({"target": "h", "cam_creds": "0"}).cam_creds is False


# --- frontend exposes the control -----------------------------------------
def test_page_has_cam_creds_control():
    with _running_server() as base:
        body = httpx.get(base + "/", timeout=5).text
    assert 'id="cam_creds"' in body
    assert 'p.set("cam_creds"' in body        # the form sends it on every scan
