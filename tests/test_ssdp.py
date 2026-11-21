"""SSDP / UPnP device enumeration (UDP 1900). Unicast M-SEARCH (ssdp:all) ->
SERVER / LOCATION / ST / USN, then a read-only fetch of the device-description
XML (keeping the scanned host, never the advertised LAN IP). UPnP discovery is
unauthenticated by design, so the finding is INFORMATIONAL (not an alert).
Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


_SERVER = "Linux/5.4 UPnP/1.0 Example-Router/2.1"
_LOCATION_TMPL = "http://10.9.9.9:{port}/desc.xml"

_DESC_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Example Home Router</friendlyName>
  <manufacturer>ExampleCorp</manufacturer>
  <modelName>EX-1200</modelName>
  <modelNumber>2.1</modelNumber>
  <serviceList>
   <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType></service>
   <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service>
  </serviceList>
 </device>
</root>"""


def _msearch_response(location: str) -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "EXT:\r\n"
        f"LOCATION: {location}\r\n"
        f"SERVER: {_SERVER}\r\n"
        "ST: upnp:rootdevice\r\n"
        "USN: uuid:abcd::upnp:rootdevice\r\n\r\n"
    ).encode()


# --- header / URL / description parsing -------------------------------------
def test_ssdp_headers_parse():
    h = fp._ssdp_headers(_msearch_response("http://x/d.xml").decode())
    assert h["server"] == _SERVER
    assert h["location"] == "http://x/d.xml"
    assert h["st"] == "upnp:rootdevice"


def test_location_parts_keeps_only_port_path_scheme():
    assert fp._ssdp_location_parts("http://10.0.0.1:49152/desc.xml") == \
        ("/desc.xml", 49152, False)
    assert fp._ssdp_location_parts("https://host/d") == ("/d", 443, True)
    assert fp._ssdp_location_parts("ftp://x/y") is None


def test_parse_upnp_desc_fields_and_services():
    d = fp._parse_upnp_desc(_DESC_XML)
    assert d["manufacturer"] == "ExampleCorp"
    assert d["model"] == "EX-1200"
    assert d["model_number"] == "2.1"
    assert any("WANIPConnection" in s for s in d["services"])
    assert len(d["services"]) == 2


# --- ssdp_probe over a UDP mock ---------------------------------------------
def test_ssdp_probe_end_to_end():
    async def run():
        loop = asyncio.get_event_loop()

        class Srv(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                if b"M-SEARCH" in data:
                    self.t.sendto(_msearch_response("http://10.9.9.9:80/d.xml"),
                                  addr)

        transport, _p = await loop.create_datagram_endpoint(
            Srv, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        try:
            return await fp.ssdp_probe("127.0.0.1", port, 1.0)
        finally:
            transport.close()

    res = asyncio.run(run())
    assert res is not None
    assert res["server"] == _SERVER
    assert res["locations"] == ["http://10.9.9.9:80/d.xml"]
    assert "upnp:rootdevice" in res["sts"]


def test_ssdp_probe_timeout_returns_none():
    async def run():
        return await fp.ssdp_probe("127.0.0.1", 59998, 0.3)
    assert asyncio.run(run()) is None


# --- ssdp_describe keeps the scanned host -----------------------------------
def test_ssdp_describe_uses_scanned_host_not_advertised_ip():
    # LOCATION advertises 10.9.9.9 but the XML is served on 127.0.0.1; describe
    # must adopt only the port/path and fetch from the scanned host.
    async def run():
        async def handler(reader, writer):
            await asyncio.wait_for(reader.read(1024), timeout=2.0)
            body = _DESC_XML.encode()
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n"
                         b"Connection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()

        srv = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.ssdp_describe(
                "127.0.0.1", _LOCATION_TMPL.format(port=port), 1.0)
        finally:
            srv.close()
            await srv.wait_closed()

    d = asyncio.run(run())
    assert d["model"] == "EX-1200" and d["manufacturer"] == "ExampleCorp"


# --- host-level wiring in run_exposure_checks -------------------------------
def test_run_exposure_checks_adds_ssdp_service(monkeypatch):
    async def fake_probe(host, port, timeout):
        return {"server": _SERVER,
                "locations": ["http://10.9.9.9:49152/desc.xml"],
                "sts": ["upnp:rootdevice"], "usns": ["uuid:abcd::upnp:rootdevice"]}

    async def fake_desc(host, location, timeout):
        return fp._parse_upnp_desc(_DESC_XML)

    monkeypatch.setattr(fp, "ssdp_probe", fake_probe)
    monkeypatch.setattr(fp, "ssdp_describe", fake_desc)

    async def run():
        services = [Service(port=22, name="ssh", state="open")]
        cfg = ScanConfig(target="x", timeout=0.3, concurrency=5)
        await fp.run_exposure_checks(cfg, "127.0.0.1", services)
        return services

    services = asyncio.run(run())
    upnp = next((s for s in services if s.port == 1900 and s.proto == "udp"), None)
    assert upnp is not None
    scr = next(s for s in upnp.scripts if s["id"] == "ssdp-upnp")
    # informational, never an alert
    assert "ssdp-upnp" not in fp.EXPOSURE_ALERT_IDS
    # enrichment: product + version recovered, IGD hardening note present
    assert upnp.product == "ExampleCorp EX-1200"
    assert upnp.version == "2.1"
    assert "WANIPConnection" in scr["output"]
    assert "Internet Gateway" in scr["output"]
