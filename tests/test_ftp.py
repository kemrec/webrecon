"""Anonymous-FTP posture (TCP 21, RFC 959).

The 220 greeting leaks the banner; USER anonymous / PASS tells whether anonymous
access is allowed (230 = alert) or refused (530). No listing or transfer is
performed. Loopback mock FTP server only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _ftp_server(*, allow_anon=True, need_pass=True,
                greet=b"220 (vsFTPd 3.0.5)\r\n", multiline=False):
    async def handler(reader, writer):
        if multiline:
            writer.write(b"220-Welcome\r\n220 ready\r\n")
        else:
            writer.write(greet)
        await writer.drain()
        # USER
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=2.0)
        except Exception:
            writer.close()
            return
        if not need_pass:
            writer.write(b"230 Logged in\r\n" if allow_anon
                         else b"530 Login incorrect\r\n")
        else:
            writer.write(b"331 Please specify the password\r\n")
            await writer.drain()
            try:
                await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=2.0)
            except Exception:
                writer.close()
                return
            writer.write(b"230 Login successful\r\n" if allow_anon
                         else b"530 Login incorrect\r\n")
        try:
            await writer.drain()
            await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=1.0)   # QUIT
        except Exception:
            pass
        writer.close()
    return handler


def _probe(server):
    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.ftp_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- probe ------------------------------------------------------------------
def test_anonymous_allowed_with_password_step():
    res = _probe(_ftp_server(allow_anon=True))
    assert res["anon"] is True
    assert "vsFTPd" in res["banner"]


def test_anonymous_refused():
    res = _probe(_ftp_server(allow_anon=False))
    assert res["anon"] is False


def test_anonymous_allowed_no_password():
    res = _probe(_ftp_server(allow_anon=True, need_pass=False))
    assert res["anon"] is True


def test_multiline_greeting():
    # multi-line 220-/220 greeting: the first line's text is captured as banner
    res = _probe(_ftp_server(multiline=True))
    assert res["anon"] is True
    assert res["banner"] == "Welcome"


def test_non_ftp_is_none():
    async def bad(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH\r\n")
        writer.close()
    assert _probe(bad) is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(server):
    svc = Service(port=0, name="ftp", state="open")

    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_anon_is_alert():
    svc = _dispatch(_ftp_server(allow_anon=True))
    ids = {s["id"] for s in svc.scripts}
    assert "ftp-anon" in ids
    assert "ftp-banner" in ids
    assert "ftp-anon" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"


def test_dispatch_refused_no_alert():
    svc = _dispatch(_ftp_server(allow_anon=False))
    ids = {s["id"] for s in svc.scripts}
    assert "ftp-anon-refused" in ids
    assert "ftp-anon" not in ids
    assert svc.confidence != "high"
