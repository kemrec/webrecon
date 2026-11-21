"""Vendor private binary protocols: Dahua DVRIP (37777) + Hikvision SDK (8000).
Read-only detection. Loopback servers only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _serve(payload: bytes, *, expect_bytes: bool = False, greet: bool = False):
    """A loopback TCP server. If greet, it writes `payload` immediately on
    connect (Hikvision style). Else it reads the request first (Dahua style);
    when expect_bytes it only replies if the client actually sent something."""
    async def handler(reader, writer):
        try:
            if greet:
                writer.write(payload)
            else:
                data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                if payload and (data or not expect_bytes):
                    writer.write(payload)
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _run(handler, probe, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await probe("127.0.0.1", port, timeout)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- Dahua DVRIP ------------------------------------------------------------
def test_dvrip_realm_request_shape():
    req = fp._DVRIP_REALM_REQ
    assert len(req) == 32
    assert req[:4] == b"\xa0\x01\x00\x00"            # realm-request type
    assert req[4:24] == b"\x00" * 20                 # no credentials
    assert req[24:] == b"\x05\x02\x01\x01\x00\x00\xa1\xaa"


def test_parse_dvrip_text_realm():
    body = b"\xb0\x01\x00\x68" + b"\x00" * 28 + b"Realm:Login to AA12345\r\nRandom:987654\r\n"
    out = fp._parse_dvrip(body)
    assert out["realm"] == "Login to AA12345"
    assert out["random"] == "987654"


def test_parse_dvrip_binary_header_only():
    # a DHIP/JSON recv header (0xf6) with no text realm still identifies Dahua
    out = fp._parse_dvrip(b"\xf6\x00\x00\x68" + b"\x00" * 28)
    assert out == {"realm": "", "random": ""}


def test_parse_dvrip_rejects_unrelated():
    assert fp._parse_dvrip(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert fp._parse_dvrip(b"\x00\x00") is None


def test_dahua_dvrip_probe_end_to_end():
    resp = b"\xb0\x01\x00\x68" + b"\x00" * 28 + b"Realm:Login to DH9988\r\nRandom:42\r\n"
    out = _run(_serve(resp), fp.dahua_dvrip_probe)
    assert out is not None and out["realm"] == "Login to DH9988"


def test_dahua_dvrip_probe_silent_is_none():
    assert _run(_serve(b""), fp.dahua_dvrip_probe) is None


# --- Hikvision SDK ----------------------------------------------------------
def test_hik_handshake_matches_both_known_variants():
    ipcam = b"\x00\x00\x00\x10\x00\x00\x00\x1e\x00\x00\x00\x1e\x00\x00\x00\x00"
    hikcn = b"\x00\x00\x00\x10\x00\x00\x00\x0d\x00\x00\x00\x0d\x00\x00\x00\x00"
    assert fp._hik_sdk_handshake(ipcam)
    assert fp._hik_sdk_handshake(hikcn)


def test_hik_handshake_rejects_mismatch_and_http():
    # unequal XX pair, and a plain HTTP greeting
    assert not fp._hik_sdk_handshake(
        b"\x00\x00\x00\x10\x00\x00\x00\x1e\x00\x00\x00\x0d\x00\x00\x00\x00")
    assert not fp._hik_sdk_handshake(b"HTTP/1.1 200 OK\r\n\r\n")
    assert not fp._hik_sdk_handshake(b"\x00\x00\x00\x10")


def test_hikvision_sdk_probe_end_to_end():
    greeting = b"\x00\x00\x00\x10\x00\x00\x00\x1e\x00\x00\x00\x1e\x00\x00\x00\x00"
    assert _run(_serve(greeting, greet=True), fp.hikvision_sdk_probe) is True


def test_hikvision_sdk_probe_silent_http_is_false():
    # a server that says nothing until spoken to (like HTTP) -> not Hikvision SDK
    assert _run(_serve(b"", expect_bytes=True), fp.hikvision_sdk_probe) is False


# --- check_exposure dispatch ------------------------------------------------
def _check(name, handler, port=0):
    svc = Service(port=port, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(handler, "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0), "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_marks_dahua_dvrip():
    resp = b"\xb0\x01\x00\x68" + b"\x00" * 28 + b"Realm:Login to DH1\r\nRandom:1\r\n"
    svc = _check("dvrip", _serve(resp))
    ids = {s["id"] for s in svc.scripts}
    assert "dahua-dvrip" in ids
    assert svc.product == "Dahua"
    # informational detection, not an unauth-breach alert
    assert "dahua-dvrip" not in fp.EXPOSURE_ALERT_IDS
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "Login to DH1" in out["dahua-dvrip"]


def test_dispatch_marks_hikvision_sdk():
    greeting = b"\x00\x00\x00\x10\x00\x00\x00\x1e\x00\x00\x00\x1e\x00\x00\x00\x00"
    svc = _check("hikvision", _serve(greeting, greet=True))
    ids = {s["id"] for s in svc.scripts}
    assert "hikvision-sdk" in ids
    assert svc.product == "Hikvision"
    assert "hikvision-sdk" not in fp.EXPOSURE_ALERT_IDS


def test_dispatch_hikvision_miss_falls_through_to_onvif():
    # a silent server on an 8000-like dispatch (by name) must not be mislabelled
    # Hikvision, and must not raise -- it falls through to the ONVIF/web branch.
    svc = _check("hikvision", _serve(b"", expect_bytes=True))
    assert "hikvision-sdk" not in {s["id"] for s in svc.scripts}
