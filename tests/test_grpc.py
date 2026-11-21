"""gRPC/HTTP2 detection (dependency-free h2c preface + TLS ALPN) and the
reflection-enum wiring. Loopback servers only; reflection tooling is stubbed so
the tests are deterministic regardless of whether grpcurl/grpcio are installed."""
import asyncio
import ssl

import pytest

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _ids(svc):
    return {s["id"] for s in svc.scripts}


def test_h2_frame_and_settings_helpers():
    f = fp._h2_frame(0x04, 0)
    assert f == b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    assert fp._is_h2_settings(f)
    assert not fp._is_h2_settings(b"HTTP/1.1 400 Bad Request\r\n")
    assert not fp._is_h2_settings(b"\x00\x00\x00\x01\x00\x00\x00\x00\x00")  # HEADERS


def test_parse_grpcurl_list():
    out = fp._parse_grpcurl_list(
        "grpc.health.v1.Health\n"
        "grpc.reflection.v1alpha.ServerReflection\n"
        "myapp.v1.OrderService\n"
        "\nFailed to list services: some error\n")
    assert "grpc.health.v1.Health" in out
    assert "myapp.v1.OrderService" in out
    assert not any(" " in s for s in out)          # error line dropped


def test_h2c_detection_end_to_end():
    async def server(reader, writer):
        try:
            await asyncio.wait_for(reader.read(64), timeout=2.0)
        except Exception:
            pass
        writer.write(fp._h2_frame(0x04, 0))         # reply with a SETTINGS frame
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()

    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_probe("127.0.0.1", port, 2.0, tls=False)
        finally:
            srv.close()
            await srv.wait_closed()

    det = asyncio.run(run())
    assert det is not None and "h2c" in det["transport"]


def test_h2c_detection_negative_on_http1():
    async def server(reader, writer):
        try:
            await asyncio.wait_for(reader.read(64), timeout=2.0)
        except Exception:
            pass
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()

    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_probe("127.0.0.1", port, 2.0, tls=False)
        finally:
            srv.close()
            await srv.wait_closed()

    assert asyncio.run(run()) is None


def _selfsigned():
    pytest.importorskip("cryptography")
    import datetime
    import os
    import tempfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cp, kp


def test_h2_alpn_detection_over_tls():
    cp, kp = _selfsigned()

    async def run():
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cp, kp)
        sctx.set_alpn_protocols(["h2"])
        srv = await asyncio.start_server(lambda r, w: w.close(),
                                         "127.0.0.1", 0, ssl=sctx)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_probe("127.0.0.1", port, 3.0, tls=True)
        finally:
            srv.close()
            await srv.wait_closed()

    det = asyncio.run(run())
    assert det is not None and det["transport"].startswith("h2 (ALPN")


def _run_check(monkeypatch, det, refl, port=50051, name="", tls=None):
    async def fake_probe(host, p, timeout, tlsd):
        return det

    async def fake_list(host, p, timeout, tlsd):
        return refl

    monkeypatch.setattr(fp, "grpc_probe", fake_probe)
    monkeypatch.setattr(fp, "grpc_list_services", fake_list)

    async def run():
        svc = Service(port=port, name=name, state="open")
        if tls:
            svc.tls = tls
        cfg = ScanConfig(target="x", timeout=1.0, concurrency=5)
        await fp.check_exposure(cfg, "127.0.0.1", svc)
        return svc

    return asyncio.run(run())


def test_grpc_reflection_exposed_is_alert(monkeypatch):
    svc = _run_check(
        monkeypatch,
        det={"transport": "h2c (cleartext)"},
        refl={"tool": "grpcurl",
              "services": ["grpc.health.v1.Health", "myapp.v1.OrderService"]})
    assert "grpc-reflection-exposed" in _ids(svc)
    assert "grpc-reflection-exposed" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "myapp.v1.OrderService" in out["grpc-reflection-exposed"]


def test_grpc_detected_note_when_no_tool(monkeypatch):
    svc = _run_check(monkeypatch,
                     det={"transport": "h2c (cleartext)"}, refl=None)
    assert "grpc-detected" in _ids(svc)
    assert "grpc-reflection-exposed" not in _ids(svc)
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "install grpcurl or grpcio" in out["grpc-detected"]


def test_grpc_detected_note_when_reflection_off(monkeypatch):
    svc = _run_check(monkeypatch, det={"transport": "h2 (ALPN, TLS)"},
                     refl={"tool": "grpcurl", "services": []})
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "grpc-detected" in out
    assert "reflection is disabled" in out["grpc-detected"]


def test_grpc_branch_skipped_on_non_grpc_port(monkeypatch):
    # even if grpc_probe would answer, a plain web port must not enter the branch
    svc = _run_check(monkeypatch, det={"transport": "h2c (cleartext)"},
                     refl={"tool": "grpcurl", "services": ["x.Y"]},
                     port=8080, name="http")
    assert not any(i.startswith("grpc") for i in _ids(svc))


# --- native (dependency-free) reflection --------------------------------------
def _uvarint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out


def _ld(field, data):
    return bytes([(field << 3) | 2]) + _uvarint(len(data)) + data


def _refl_response_bytes(services):
    # ServerReflectionResponse(6) -> repeated ServiceResponse(1) -> name(1)
    inner = b"".join(_ld(1, _ld(1, s.encode())) for s in services)
    resp = _ld(6, inner)
    return b"\x00" + len(resp).to_bytes(4, "big") + resp


def _make_h2_server(mode, services=()):
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(2048), timeout=2.0)
        except Exception:
            pass
        try:
            writer.write(fp._h2_frame(0x04, 0))                       # SETTINGS
            if mode == "services":
                writer.write(fp._h2_frame(0x01, 1, b"", flags=0x04))  # HEADERS
                writer.write(fp._h2_frame(0x00, 1, _refl_response_bytes(services),
                                          flags=0x01))                 # DATA END_STREAM
            elif mode == "refloff":
                writer.write(fp._h2_frame(0x01, 1, b"", flags=0x05))  # trailers-only
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def test_hpack_literal_and_protobuf_helpers():
    assert fp._hpack_literal(":path", "/x") == b"\x00\x05:path\x02/x"
    assert fp._varint(bytes([0x96, 0x01]), 0) == (150, 2)
    resp = _refl_response_bytes(["svc.One", "svc.Two"])
    assert fp._parse_reflection_services(resp) == ["svc.One", "svc.Two"]


def test_grpc_reflect_native_lists_services():
    async def run():
        srv = await asyncio.start_server(
            _make_h2_server("services",
                            ["grpc.health.v1.Health", "myapp.v1.OrderService"]),
            "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_reflect_native("127.0.0.1", port, 2.0, tls=False)
        finally:
            srv.close()
            await srv.wait_closed()

    spoke, svcs = asyncio.run(run())
    assert spoke is True
    assert svcs == ["grpc.health.v1.Health", "myapp.v1.OrderService"]


def test_grpc_reflect_native_reflection_off():
    async def run():
        srv = await asyncio.start_server(_make_h2_server("refloff"),
                                         "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_reflect_native("127.0.0.1", port, 2.0, tls=False)
        finally:
            srv.close()
            await srv.wait_closed()

    spoke, svcs = asyncio.run(run())
    assert spoke is True and svcs == []


def test_grpc_reflect_native_not_grpc():
    spoke, svcs = asyncio.run(
        fp.grpc_reflect_native("127.0.0.1", 59998, 0.3, tls=False))
    assert spoke is False and svcs == []


def test_grpc_native_integration_reflection_exposed():
    # full check_exposure path, no monkeypatch: native detection + native enum
    async def run():
        srv = await asyncio.start_server(
            _make_h2_server("services", ["a.Svc", "b.Svc"]), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        svc = Service(port=port, name="grpc", state="open")
        cfg = ScanConfig(target="x", timeout=2.0, concurrency=5)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
        return svc

    svc = asyncio.run(run())
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "grpc-reflection-exposed" in out
    assert "via native" in out["grpc-reflection-exposed"]
    assert "a.Svc" in out["grpc-reflection-exposed"]
