"""VNC / RFB security-type posture (TCP 5900).

The server lists the security types it will accept; type 1 ('None') means it
grants a full desktop session with no authentication (the alert). The probe
only reads the offered types -- it never selects one. Loopback mock server."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _rfb37_server(types, version=b"RFB 003.008\n"):
    async def handler(reader, writer):
        writer.write(version)
        try:
            await asyncio.wait_for(reader.readexactly(12), timeout=2.0)
        except Exception:
            writer.close()
            return
        writer.write(bytes([len(types)]) + bytes(types))
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _rfb33_server(sectype):
    async def handler(reader, writer):
        writer.write(b"RFB 003.003\n")
        try:
            await asyncio.wait_for(reader.readexactly(12), timeout=2.0)
        except Exception:
            writer.close()
            return
        writer.write(sectype.to_bytes(4, "big"))
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(server):
    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.vnc_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- probe ------------------------------------------------------------------
def test_none_and_vncauth_offered():
    res = _probe(_rfb37_server([1, 2]))
    assert res["version"] == "3.8"
    assert res["types"] == [1, 2]


def test_vncauth_only():
    res = _probe(_rfb37_server([2]))
    assert res["types"] == [2]


def test_rfb33_single_type_none():
    res = _probe(_rfb33_server(1))
    assert res["version"] == "3.3"
    assert res["types"] == [1]


def test_non_rfb_is_none():
    async def bad(reader, writer):
        writer.write(b"SSH-2.0-x\r\n")
        writer.close()
    assert _probe(bad) is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(server):
    svc = Service(port=0, name="vnc", state="open")

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


def test_dispatch_none_is_alert():
    svc = _dispatch(_rfb37_server([1, 2]))
    ids = {s["id"] for s in svc.scripts}
    assert "vnc-security-types" in ids
    assert "vnc-none-auth" in ids
    assert "vnc-none-auth" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"
    assert svc.product == "VNC"


def test_dispatch_vncauth_only_no_alert():
    svc = _dispatch(_rfb37_server([2]))
    ids = {s["id"] for s in svc.scripts}
    assert "vnc-security-types" in ids
    assert "vnc-none-auth" not in ids
    assert svc.confidence != "high"
