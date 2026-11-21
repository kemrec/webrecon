"""Native gRPC method-descriptor enumeration (reflection file_containing_symbol
-> FileDescriptorProto -> service/method names). Loopback h2c server only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


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


def _method(name):
    # MethodDescriptorProto: field 1 = name
    return _ld(1, name.encode())


def _service(name, methods):
    # ServiceDescriptorProto: 1=name, 2=repeated method
    return _ld(1, name.encode()) + b"".join(_ld(2, _method(m)) for m in methods)


def _fdp(package, services):
    # FileDescriptorProto: 2=package, 6=repeated service
    body = _ld(2, package.encode())
    for sname, methods in services:
        body += _ld(6, _service(sname, methods))
    return body


def _file_response_frame(package, services):
    # ServerReflectionResponse: 4 = FileDescriptorResponse {1 = repeated bytes fdp}
    fileresp = _ld(1, _fdp(package, services))
    resp = _ld(4, fileresp)
    return b"\x00" + len(resp).to_bytes(4, "big") + resp


# --- pure protobuf helpers --------------------------------------------------
def test_pb_varint_roundtrip():
    assert fp._pb_varint(0) == b"\x00"
    assert fp._pb_varint(1) == b"\x01"
    assert fp._pb_varint(150) == b"\x96\x01"


def test_grpc_symbol_msg_shape():
    msg = fp._grpc_symbol_msg("myapp.v1.OrderService")
    assert msg[0] == 0x00                                  # gRPC uncompressed flag
    assert int.from_bytes(msg[1:5], "big") == len(msg) - 5
    assert msg[5] == 0x22                                  # field 4, wiretype 2
    assert b"myapp.v1.OrderService" in msg


def test_parse_fdp_services_extracts_methods():
    fdp = _fdp("myapp.v1", [("OrderService", ["GetOrder", "ListOrders"])])
    out = fp._parse_fdp_services(fdp)
    assert out == {"myapp.v1.OrderService": ["GetOrder", "ListOrders"]}


def test_parse_fdp_services_no_package():
    fdp = _fdp("", [("Bare", ["Ping"])])
    assert fp._parse_fdp_services(fdp) == {"Bare": ["Ping"]}


def test_parse_reflection_file_response_merges():
    frame = _file_response_frame(
        "myapp.v1", [("OrderService", ["GetOrder", "ListOrders"]),
                     ("AdminService", ["DeleteAll"])])
    out = fp._parse_reflection_file_response(frame)
    assert out["myapp.v1.OrderService"] == ["GetOrder", "ListOrders"]
    assert out["myapp.v1.AdminService"] == ["DeleteAll"]


# --- end-to-end against a loopback h2c server -------------------------------
def _symbol_server(fdp_map):
    """h2c server that answers each file_containing_symbol with the matching
    FileDescriptorResponse. fdp_map: {symbol: (package, [(svc, [methods])])}."""
    def handler_factory():
        async def handler(reader, writer):
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=2.0)
            except Exception:
                data = b""
            # find which requested symbol the DATA frame carried
            chosen = None
            for sym in fdp_map:
                if sym.encode() in data:
                    chosen = sym
                    break
            try:
                writer.write(fp._h2_frame(0x04, 0))                    # SETTINGS
                writer.write(fp._h2_frame(0x01, 1, b"", flags=0x04))   # HEADERS
                if chosen is not None:
                    pkg, svcs = fdp_map[chosen]
                    writer.write(fp._h2_frame(
                        0x00, 1, _file_response_frame(pkg, svcs), flags=0x01))
                else:
                    writer.write(fp._h2_frame(0x00, 1, b"", flags=0x01))
                await writer.drain()
            except Exception:
                pass
            writer.close()
        return handler
    return handler_factory()


def test_grpc_reflect_methods_native_end_to_end():
    fdp_map = {"myapp.v1.OrderService":
               ("myapp.v1", [("OrderService", ["GetOrder", "ListOrders"])])}

    async def run():
        srv = await asyncio.start_server(_symbol_server(fdp_map), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.grpc_reflect_methods_native(
                "127.0.0.1", port, 2.0, False, ["myapp.v1.OrderService"])
        finally:
            srv.close()
            await srv.wait_closed()

    out = asyncio.run(run())
    assert out == {"myapp.v1.OrderService": ["GetOrder", "ListOrders"]}


def test_grpc_reflect_methods_native_bounded():
    # max_services caps how many symbols we ask for
    calls = {"n": 0}
    real = fp._reflect_once

    async def counting(host, port, timeout, tls, path, req_msg=None):
        calls["n"] += 1
        return False, b""

    import servicescan.fingerprint as mod
    mod._reflect_once = counting
    try:
        out = asyncio.run(mod.grpc_reflect_methods_native(
            "127.0.0.1", 1, 0.1, False, [f"s{i}.S" for i in range(50)],
            max_services=3))
    finally:
        mod._reflect_once = real
    # 3 symbols x 2 reflection paths = at most 6 exchanges
    assert out == {} and calls["n"] <= 6


def test_check_exposure_emits_grpc_methods(monkeypatch):
    async def fake_probe(host, p, timeout, tlsd):
        return {"transport": "h2c (cleartext)"}

    async def fake_list(host, p, timeout, tlsd):
        return {"tool": "native", "services": ["myapp.v1.OrderService"]}

    async def fake_methods(host, p, timeout, tlsd, services, max_services=10):
        return {"myapp.v1.OrderService": ["GetOrder", "ListOrders"]}

    monkeypatch.setattr(fp, "grpc_probe", fake_probe)
    monkeypatch.setattr(fp, "grpc_list_services", fake_list)
    monkeypatch.setattr(fp, "grpc_reflect_methods_native", fake_methods)

    async def run():
        svc = Service(port=50051, name="grpc", state="open")
        await fp.check_exposure(ScanConfig(target="x", timeout=1.0), "127.0.0.1", svc)
        return svc

    svc = asyncio.run(run())
    ids = {s["id"] for s in svc.scripts}
    assert "grpc-reflection-exposed" in ids
    assert "grpc-methods" in ids
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "GetOrder" in out["grpc-methods"]
    assert "myapp.v1.OrderService" in out["grpc-methods"]
    # the method script is detail, not a critical alert on its own
    assert "grpc-methods" not in fp.EXPOSURE_ALERT_IDS
