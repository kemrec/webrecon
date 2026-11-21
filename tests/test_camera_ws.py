"""Camera WebSocket video-preview exposure (Hikvision ws 7681 / wss 7682, or any
camera-signalled port). Read-only: unauth RFC6455 upgrade, then observe whether
the device volunteers binary video frames without credentials. Loopback only."""
import asyncio
import re

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- RFC6455 handshake math + frame decoding --------------------------------
def test_ws_accept_rfc6455_vector():
    # the canonical example from RFC6455 section 1.3
    assert fp._ws_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def _server_frame(opcode: int, payload: bytes) -> bytes:
    hdr = bytes([0x80 | opcode])                       # FIN + opcode, unmasked
    n = len(payload)
    if n < 126:
        hdr += bytes([n])
    elif n < 65536:
        hdr += bytes([126]) + n.to_bytes(2, "big")
    else:
        hdr += bytes([127]) + n.to_bytes(8, "big")
    return hdr + payload


def test_ws_decode_frames_text_and_binary():
    buf = _server_frame(0x1, b"hello") + _server_frame(0x2, b"\x00\x00\x00\x01xyz")
    frames = fp._ws_decode_frames(buf)
    assert (0x1, b"hello") in frames
    assert any(op == 0x2 and pl.startswith(b"\x00\x00\x00\x01") for op, pl in frames)


def test_ws_decode_frames_extended_length():
    payload = b"V" * 300                                # forces the 126 length form
    frames = fp._ws_decode_frames(_server_frame(0x2, payload))
    assert frames == [(0x2, payload)]


def test_ws_decode_frames_ignores_partial_trailing():
    good = _server_frame(0x2, b"abc")
    assert fp._ws_decode_frames(good + b"\x82\x7f\x00") == [(0x2, b"abc")]


# --- mock WebSocket server --------------------------------------------------
def _ws_server(mode: str):
    async def handler(reader, writer):
        try:
            req = await asyncio.wait_for(reader.read(2048), timeout=2.0)
        except Exception:
            req = b""
        m = re.search(rb"Sec-WebSocket-Key:\s*([^\r\n]+)\r\n", req)
        key = m.group(1).decode().strip() if m else ""
        try:
            if mode == "http":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nhi")
            elif mode == "auth":
                writer.write(b"HTTP/1.1 401 Unauthorized\r\n"
                             b"WWW-Authenticate: Basic realm=\"x\"\r\n"
                             b"Connection: close\r\n\r\n")
            else:
                accept = fp._ws_accept(key)
                writer.write(
                    f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    .encode())
                if mode == "stream":
                    # a binary (video) frame volunteered with no auth step
                    writer.write(_server_frame(0x2, b"\x00\x00\x00\x01" + b"\x67" * 400))
                # mode == "idle": 101 then nothing
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_ws_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.ws_stream_probe("127.0.0.1", port, timeout, False)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_ws_probe_anonymous_binary_stream():
    r = _probe("stream")
    assert r is not None
    assert r["upgraded"] and r["accept_ok"] and r["binary"]
    assert r["video_bytes"] >= 400


def test_ws_probe_upgrade_but_no_frames():
    r = _probe("idle")
    assert r is not None
    assert r["upgraded"] and r["accept_ok"] and not r["binary"]


def test_ws_probe_auth_refused():
    r = _probe("auth")
    assert r is not None
    assert r["auth"] is True and not r["upgraded"]


def test_ws_probe_plain_http_is_none():
    assert _probe("http") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="http", server_hdr="Hikvision-Webs"):
    svc = Service(port=0, name=name, state="open")
    svc.http = {"server": server_hdr}

    async def run():
        srv = await asyncio.start_server(_ws_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_anonymous_stream_is_alert():
    svc = _check("stream")
    ids = {s["id"] for s in svc.scripts}
    assert "camera-ws-stream-unauth" in ids
    assert "camera-ws-stream-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "UNAUTHENTICATED" in svc.extrainfo


def test_dispatch_upgrade_only_is_informational():
    svc = _check("idle")
    ids = {s["id"] for s in svc.scripts}
    assert "camera-ws-preview" in ids
    assert "camera-ws-preview" not in fp.EXPOSURE_ALERT_IDS
    # not over-claimed as a confirmed anonymous stream
    assert "camera-ws-stream-unauth" not in ids


def test_dispatch_non_camera_web_port_not_probed():
    # no camera signal -> the WebSocket preview probe must not run at all
    svc = _check("stream", server_hdr="nginx")
    assert not any(i.startswith("camera-ws") for i in svc.scripts)
