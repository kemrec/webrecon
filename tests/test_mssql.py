"""Microsoft SQL Server posture (TCP 1433 TDS PRELOGIN + UDP 1434 Browser).

Both are unauthenticated, read-only identity leaks: PRELOGIN returns the server
version and TLS/encryption posture without a login; the SQL Server Browser lists
every instance's name/version/port. Informational. Loopback mocks only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- TDS PRELOGIN (TCP) -----------------------------------------------------
def _prelogin_resp(version=(15, 0, 2000), enc=0x00):
    vdata = bytes([version[0], version[1]]) + version[2].to_bytes(2, "big") + b"\x00\x00"
    table = (b"\x00" + (11).to_bytes(2, "big") + (6).to_bytes(2, "big")
             + b"\x01" + (17).to_bytes(2, "big") + (1).to_bytes(2, "big")
             + b"\xff")
    payload = table + vdata + bytes([enc])
    return b"\x04\x01" + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00\x00\x00" + payload


def _tcp_server(resp):
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(512), timeout=2.0)
        except Exception:
            pass
        writer.write(resp)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe_tcp(resp):
    async def run():
        srv = await asyncio.start_server(_tcp_server(resp), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.mssql_prelogin_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_prelogin_version_and_encryption():
    res = _probe_tcp(_prelogin_resp(version=(15, 0, 2000), enc=0x00))
    assert res["version"] == "15.0.2000"
    assert res["encryption"] == "off (login-only)"


def test_prelogin_no_tls_flag():
    res = _probe_tcp(_prelogin_resp(enc=0x02))
    assert res["encryption"] == "not supported"


def test_prelogin_wrong_packet_is_none():
    assert _probe_tcp(b"\x12\x01\x00\x08\x00\x00\x00\x00") is None   # not type 0x04


# --- SQL Server Browser (UDP) ----------------------------------------------
def _browser_payload(body: str):
    b = body.encode()
    return b"\x05" + len(b).to_bytes(2, "little") + b


def _probe_udp(payload):
    async def run():
        loop = asyncio.get_event_loop()

        class Srv(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                self.t.sendto(payload, addr)

        transport, _ = await loop.create_datagram_endpoint(
            Srv, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("socket").getsockname()[1]
        try:
            return await fp.mssql_browser_probe("127.0.0.1", port, 1.0)
        finally:
            transport.close()
    return asyncio.run(run())


def test_browser_lists_instances():
    body = ("ServerName;SQLBOX;InstanceName;MSSQLSERVER;IsClustered;No;"
            "Version;15.0.2000.5;tcp;1433;;")
    insts = _probe_udp(_browser_payload(body))
    assert len(insts) == 1
    assert insts[0]["InstanceName"] == "MSSQLSERVER"
    assert insts[0]["Version"] == "15.0.2000.5"
    assert insts[0]["tcp"] == "1433"


def test_browser_wrong_prefix_is_none():
    assert _probe_udp(b"\x00\x00\x00nope") is None


# --- check_exposure dispatch ------------------------------------------------
def test_dispatch_prelogin_informational():
    svc = Service(port=0, name="ms-sql-s", state="open")

    async def run():
        srv = await asyncio.start_server(
            _tcp_server(_prelogin_resp(enc=0x02)), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    ids = {s["id"] for s in svc.scripts}
    assert "mssql-prelogin" in ids
    assert svc.version == "15.0.2000"
    assert svc.product == "Microsoft SQL Server"
    assert not (ids & fp.EXPOSURE_ALERT_IDS)            # informational
    out = next(s["output"] for s in svc.scripts if s["id"] == "mssql-prelogin")
    assert "NO TLS" in out                              # enc not-supported flagged


def test_dispatch_browser_udp():
    svc = Service(port=1434, proto="udp", name="ms-sql-m", state="open")
    body = "ServerName;DB1;InstanceName;SQLEXPRESS;Version;16.0.1000.6;tcp;1433;;"

    async def run():
        loop = asyncio.get_event_loop()

        class Srv(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                self.t.sendto(_browser_payload(body), addr)

        transport, _ = await loop.create_datagram_endpoint(
            Srv, local_addr=("127.0.0.1", 0))
        svc.port = transport.get_extra_info("socket").getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            transport.close()
    asyncio.run(run())
    ids = {s["id"] for s in svc.scripts}
    assert "mssql-browser" in ids
    assert svc.version == "16.0.1000.6"
    assert not (ids & fp.EXPOSURE_ALERT_IDS)
