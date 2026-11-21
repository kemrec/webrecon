"""MSRPC IOXIDResolver interface-leak posture (TCP 135).

An unauthenticated DCE/RPC bind + ServerAlive2 (opnum 5) returns the host's
network interface bindings (DUALSTRINGARRAY) with no credential -- an
informational topology leak. Loopback mock RPC server only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _utf16(s):
    return s.encode("utf-16-le") + b"\x00\x00"


def _bind_ack():
    # minimal connection-oriented PDU: ptype 0x0C (bind_ack), frag_length 16
    return bytes([5, 0, 0x0C, 0x03, 0x10, 0, 0, 0]) + (16).to_bytes(2, "little") \
        + (0).to_bytes(2, "little") + (1).to_bytes(4, "little")


def _serveralive2_resp(addrs):
    # response stub: a couple of NDR words, then STRINGBINDING entries
    # (wTowerId short + UTF-16LE address + NUL), then security bindings.
    stub = (12).to_bytes(4, "little") + (0).to_bytes(4, "little") \
        + (0).to_bytes(4, "little")
    for a in addrs:
        stub += (0x0007).to_bytes(2, "little") + _utf16(a)
    stub += b"\x00\x00"
    body = (len(stub)).to_bytes(4, "little") + (0).to_bytes(2, "little") \
        + b"\x00\x00" + stub                 # alloc_hint, ctx_id, cancel/reserved
    frag = 16 + len(body)
    hdr = bytes([5, 0, 0x02, 0x03, 0x10, 0, 0, 0]) + frag.to_bytes(2, "little") \
        + (0).to_bytes(2, "little") + (1).to_bytes(4, "little")
    return hdr + body


def _server(ack, resp):
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.readexactly(72), timeout=2.0)  # BIND
        except Exception:
            writer.close()
            return
        writer.write(ack)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.readexactly(24), timeout=2.0)  # request
        except Exception:
            writer.close()
            return
        if resp:
            writer.write(resp)
            try:
                await writer.drain()
            except Exception:
                pass
        writer.close()
    return handler


def _probe(ack, resp):
    async def run():
        srv = await asyncio.start_server(_server(ack, resp), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.msrpc_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- extractor --------------------------------------------------------------
def test_utf16le_addr_extraction():
    data = (0x0007).to_bytes(2, "little") + _utf16("dc01.corp.local") \
        + (0x0007).to_bytes(2, "little") + _utf16("10.0.0.5")
    assert fp._utf16le_addrs(data) == ["dc01.corp.local", "10.0.0.5"]


# --- probe ------------------------------------------------------------------
def test_serveralive2_leaks_interfaces():
    res = _probe(_bind_ack(),
                 _serveralive2_resp(["dc01.corp.local", "10.0.0.5", "fe80::1"]))
    assert res["bind_ok"] is True
    assert "dc01.corp.local" in res["interfaces"]
    assert "10.0.0.5" in res["interfaces"]
    assert "fe80::1" in res["interfaces"]


def test_bind_nak_is_none():
    nak = bytes([5, 0, 0x0D, 0x03, 0x10, 0, 0, 0]) + (16).to_bytes(2, "little") \
        + (0).to_bytes(2, "little") + (1).to_bytes(4, "little")
    assert _probe(nak, None) is None


def test_non_dcerpc_is_none():
    assert _probe(b"not-dcerpc-at-all", None) is None


# --- check_exposure dispatch ------------------------------------------------
def test_dispatch_interfaces_informational():
    svc = Service(port=0, name="msrpc", state="open")

    async def run():
        srv = await asyncio.start_server(
            _server(_bind_ack(), _serveralive2_resp(["WIN-DC.contoso.local",
                                                     "192.168.1.10"])),
            "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    ids = {s["id"] for s in svc.scripts}
    assert "msrpc-interfaces" in ids
    assert svc.product == "Microsoft Windows RPC"
    assert not (ids & fp.EXPOSURE_ALERT_IDS)            # informational leak
    out = next(s["output"] for s in svc.scripts if s["id"] == "msrpc-interfaces")
    assert "WIN-DC.contoso.local" in out
