"""rsync daemon exposure (TCP 873). List modules without auth; a module that
answers @RSYNCD: OK (no AUTHREQD) accepts anonymous access to its files = alert.
Read-only (no rsync options are sent after OK). Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _rsync_server(mode: str):
    async def handler(reader, writer):
        try:
            if mode == "notrsync":
                writer.write(b"SSH-2.0-OpenSSH_9.0\n")
                await writer.drain()
                writer.close()
                return
            writer.write(b"@RSYNCD: 31.0\n")
            await writer.drain()
            # client version line
            await asyncio.wait_for(reader.readuntil(b"\n"), timeout=2.0)
            # module request (empty = list, else a module name)
            req = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=2.0)
            if req.strip() == b"":
                writer.write(b"pub\tPublic files\n")
                writer.write(b"backup\tNightly backups\n")
                writer.write(b"@RSYNCD: EXIT\n")
            elif mode == "anon":
                writer.write(b"@RSYNCD: OK\n")
            else:                                       # auth
                writer.write(b"@RSYNCD: AUTHREQD abcd1234salt\n")
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_rsync_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.rsync_probe("127.0.0.1", port, timeout)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_anonymous_module():
    r = _probe("anon")
    assert r is not None
    assert ("pub", "Public files") in r["modules"]
    assert r["first_module"] == "pub"
    assert r["first_auth"] is False


def test_probe_auth_required_module():
    r = _probe("auth")
    assert r is not None
    assert r["first_auth"] is True
    assert len(r["modules"]) == 2


def test_probe_non_rsync_is_none():
    assert _probe("notrsync") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="rsync"):
    svc = Service(port=0, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(_rsync_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_anon_module_is_alert():
    svc = _check("anon")
    ids = {s["id"] for s in svc.scripts}
    assert "rsync-anon-module" in ids
    assert "rsync-anon-module" in fp.EXPOSURE_ALERT_IDS
    assert "rsync-modules" in ids
    assert "rsync-modules" not in fp.EXPOSURE_ALERT_IDS


def test_dispatch_auth_module_informational():
    svc = _check("auth")
    ids = {s["id"] for s in svc.scripts}
    assert "rsync-modules" in ids and "rsync-module-auth" in ids
    assert "rsync-anon-module" not in ids
