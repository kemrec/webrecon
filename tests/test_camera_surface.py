"""Camera-surface extras: unauth JPEG snapshot, ONVIF WS-Discovery (UDP),
and the _looks_like_camera gate. Loopback servers only -- no real device."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

# minimal JPEG (SOI marker FF D8 FF + JFIF APP0) -- enough for the magic check
_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"

_PROBEMATCH = (
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Body>'
    '<d:ProbeMatches><d:ProbeMatch>'
    '<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>'
    '<d:Scopes>onvif://www.onvif.org/name/TestCam '
    'onvif://www.onvif.org/hardware/IPC-9000 '
    'onvif://www.onvif.org/location/Lobby</d:Scopes>'
    '<d:XAddrs>http://127.0.0.1/onvif/device_service</d:XAddrs>'
    '</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>')


def _ids(svc):
    return {s["id"] for s in svc.scripts}


async def _http_handler(reader, writer):
    """GET /snapshot.jpg -> JPEG; everything else (incl. the ONVIF POST) -> 404."""
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
    except Exception:
        data = b""
    first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ")
    method = first[0] if first else ""
    path = first[1] if len(first) > 1 else ""
    if method == "GET" and path == "/snapshot.jpg":
        out = (b"HTTP/1.0 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: "
               + str(len(_JPEG)).encode() + b"\r\nConnection: close\r\n\r\n" + _JPEG)
    else:
        out = b"HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\n"
    try:
        writer.write(out)
        await writer.drain()
    except Exception:
        pass
    writer.close()


def _run_web(product):
    async def run():
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="http", product=product, state="open")
        cfg = ScanConfig(target="x", timeout=2.0, concurrency=5)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
        return svc
    return asyncio.run(run())


def test_looks_like_camera_gate():
    assert fp._looks_like_camera(Service(port=8080, product="Hikvision DS-2CD"))
    assert fp._looks_like_camera(Service(port=554, product="", name=""))   # RTSP port
    assert fp._looks_like_camera(Service(port=8000, product="", name=""))  # ONVIF port
    assert not fp._looks_like_camera(
        Service(port=8080, product="nginx", name="http"))


def test_camera_snapshot_unauth_detected_on_camera():
    svc = _run_web("Hikvision IP Camera")
    assert "camera-snapshot-unauth" in _ids(svc)
    assert "camera-snapshot-unauth" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "/snapshot.jpg" in out["camera-snapshot-unauth"]


def test_snapshot_not_probed_on_non_camera():
    # a plain web server with no camera signal must not get snapshot-probed
    svc = _run_web("nginx")
    assert "camera-snapshot-unauth" not in _ids(svc)


def test_parse_wsd_fields():
    wsd = fp._parse_wsd(_PROBEMATCH)
    assert "NetworkVideoTransmitter" in wsd["types"]
    assert "onvif://www.onvif.org/name/TestCam" in wsd["scopes"]
    assert wsd["xaddrs"] == "http://127.0.0.1/onvif/device_service"


def test_wsdiscovery_probe_end_to_end():
    # a UDP server that echoes a ProbeMatch to any Probe it receives
    async def run():
        loop = asyncio.get_event_loop()

        class Srv(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                self.t.sendto(_PROBEMATCH.encode(), addr)

        transport, _proto = await loop.create_datagram_endpoint(
            Srv, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        try:
            return await fp.wsdiscovery_probe("127.0.0.1", port, 2.0)
        finally:
            transport.close()

    res = asyncio.run(run())
    assert res is not None
    assert "NetworkVideoTransmitter" in res["types"]
    assert "IPC-9000" in res["scopes"]
    assert res["xaddrs"].endswith("/onvif/device_service")


def test_wsdiscovery_timeout_returns_none():
    # nothing listening -> probe must time out and return None, not raise
    async def run():
        return await fp.wsdiscovery_probe("127.0.0.1", 59999, 0.3)
    assert asyncio.run(run()) is None


def test_run_exposure_checks_adds_wsdiscovery_service(monkeypatch):
    async def fake_wsd(host, port, timeout):
        return {"types": "dn:NetworkVideoTransmitter",
                "scopes": "onvif://x/name/Cam",
                "xaddrs": "http://h/onvif/device_service"}

    monkeypatch.setattr(fp, "wsdiscovery_probe", fake_wsd)

    async def run():
        # at least one open TCP svc so run_exposure_checks doesn't early-return
        services = [Service(port=22, name="ssh", state="open")]
        cfg = ScanConfig(target="x", timeout=1.0, concurrency=5)
        await fp.run_exposure_checks(cfg, "127.0.0.1", services)
        return services

    services = asyncio.run(run())
    wsd = next((s for s in services if s.port == 3702 and s.proto == "udp"), None)
    assert wsd is not None
    assert "ws-discovery" in {s["id"] for s in wsd.scripts}
