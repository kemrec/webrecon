"""ttyd web-terminal exposure (shares the camera default port 7681 / 7682). An
unauthenticated ttyd is a browser shell = RCE, so it must be told apart from the
camera WebSocket on the same port and alerted more severely. Detection is
HTTP-layer only -- GET /, GET /token, and the Basic realm="ttyd" signature; the
/ws shell socket is never opened. Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- mock ttyd HTTP server --------------------------------------------------
# Modes mirror the real server's observable behaviour:
#   open        GET / -> 200 terminal HTML containing "ttyd"; /token -> {"token":""}
#   token_only  GET / -> 200 HTML with NO "ttyd" string; /token backstop carries it
#   auth        every path -> 401 with WWW-Authenticate: Basic realm="ttyd"
#   notttyd     GET / -> 200 "hello"; /token -> 404  (must not be detected as ttyd)
def _ttyd_server(mode: str):
    async def handler(reader, writer):
        try:
            req = await asyncio.wait_for(reader.read(2048), timeout=2.0)
        except Exception:
            req = b""
        path = b""
        if req.startswith(b"GET "):
            path = req.split(b" ", 2)[1]
        try:
            if mode == "auth":
                writer.write(b"HTTP/1.0 401 Unauthorized\r\n"
                             b'WWW-Authenticate: Basic realm="ttyd"\r\n'
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            elif path == b"/token":
                if mode in ("open", "token_only"):
                    body = b'{"token": ""}'
                    writer.write(b"HTTP/1.0 200 OK\r\n"
                                 b"Content-Type: application/json;charset=utf-8\r\n"
                                 b"Connection: close\r\n\r\n" + body)
                else:  # notttyd
                    writer.write(b"HTTP/1.0 404 Not Found\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            else:  # GET /
                if mode == "open":
                    body = b"<!doctype html><title>ttyd - Terminal</title>"
                elif mode == "token_only":
                    body = b"<!doctype html><title>Terminal</title>"
                else:  # notttyd
                    body = b"hello"
                writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
                             b"Connection: close\r\n\r\n" + body)
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, tls=False, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_ttyd_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.ttyd_probe("127.0.0.1", port, timeout, tls)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- ttyd_probe ------------------------------------------------------------
def test_probe_open_html_signature():
    r = _probe("open")
    assert r == {"auth": False}


def test_probe_open_token_backstop():
    # no "ttyd" in the page body -> must fall back to the /token JSON
    r = _probe("token_only")
    assert r == {"auth": False}


def test_probe_auth_realm_signature():
    # every path is 401; the Basic realm="ttyd" header still identifies it
    r = _probe("auth")
    assert r == {"auth": True}


def test_probe_non_ttyd_is_none():
    assert _probe("notttyd") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="ttyd"):
    svc = Service(port=0, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(_ttyd_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_open_ttyd_is_alert():
    svc = _check("open")
    ids = {s["id"] for s in svc.scripts}
    assert "ttyd-shell-unauth" in ids
    assert "ttyd-shell-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "UNAUTHENTICATED" in svc.extrainfo
    assert svc.confidence == "high"
    # no camera WebSocket probe ran on this port -- ttyd wins the shared port
    assert not any(i.startswith("camera-ws") for i in ids)


def test_dispatch_auth_ttyd_is_informational():
    svc = _check("auth")
    ids = {s["id"] for s in svc.scripts}
    assert "ttyd-shell-auth" in ids
    assert "ttyd-shell-auth" not in fp.EXPOSURE_ALERT_IDS
    # auth-enforced must not be over-claimed as an open shell
    assert "ttyd-shell-unauth" not in ids


def test_dispatch_non_ttyd_name_not_probed_off_default_port():
    # a random non-ttyd service on a non-7681 port must not trigger the probe
    svc = _check("open", name="http")
    assert not any(i.startswith("ttyd-shell") for i in svc.scripts)
