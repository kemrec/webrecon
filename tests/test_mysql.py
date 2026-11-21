"""MySQL / MariaDB handshake posture (TCP 3306).

The server sends its HandshakeV10 greeting the instant the socket opens, so a
pure read -- nothing is ever sent -- leaks the version (CVE anchor), the default
auth plugin and the TLS capability. Informational; no login is attempted.
Loopback mock server only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

_SSL = 0x0800
_SECURE = 0x8000
_PROTO41 = 0x0200
_PLUGIN_AUTH = 0x80000


def _handshake(version, ssl=True, plugin="caching_sha2_password"):
    cap_lower = _PROTO41 | _SECURE | (_SSL if ssl else 0)
    cap_upper = (_PLUGIN_AUTH >> 16) if plugin else 0
    p = b"\x0a" + version.encode() + b"\x00"
    p += b"\x11\x22\x33\x44"                    # connection id
    p += b"\x01" * 8                            # auth-plugin-data-1
    p += b"\x00"                                # filler
    p += cap_lower.to_bytes(2, "little")
    p += b"\x21"                                # charset
    p += b"\x02\x00"                            # status flags
    p += cap_upper.to_bytes(2, "little")
    p += bytes([21])                            # auth-plugin-data-len
    p += b"\x00" * 10                           # reserved
    p += b"\x02" * 13                           # auth-plugin-data-2 (SECURE set)
    if plugin:
        p += plugin.encode() + b"\x00"
    return len(p).to_bytes(3, "little") + b"\x00" + p


def _err(msg="Host '10.0.0.9' is not allowed to connect"):
    p = b"\xff" + (1130).to_bytes(2, "little") + msg.encode()
    return len(p).to_bytes(3, "little") + b"\x00" + p


def _server(packet):
    async def handler(reader, writer):
        writer.write(packet)                    # greeting is server-initiated
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(packet):
    async def run():
        srv = await asyncio.start_server(_server(packet), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.mysql_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- probe ------------------------------------------------------------------
def test_handshake_version_plugin_tls():
    res = _probe(_handshake("8.0.36"))
    assert res["version"] == "8.0.36"
    assert res["plugin"] == "caching_sha2_password"
    assert res["tls"] is True


def test_handshake_no_ssl_capability():
    res = _probe(_handshake("8.0.36", ssl=False))
    assert res["tls"] is False


def test_mariadb_version_string():
    res = _probe(_handshake("5.5.5-10.6.16-MariaDB", plugin="mysql_native_password"))
    assert res["version"] == "5.5.5-10.6.16-MariaDB"
    assert res["plugin"] == "mysql_native_password"


def test_err_packet_is_policy_refusal():
    res = _probe(_err())
    assert "not allowed" in res["err"]


def test_non_mysql_is_none():
    assert _probe(b"\x05\x00\x00\x00hello") is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(packet):
    svc = Service(port=0, name="mysql", state="open")

    async def run():
        srv = await asyncio.start_server(_server(packet), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_mysql_informational_sets_version():
    svc = _dispatch(_handshake("8.0.36"))
    ids = {s["id"] for s in svc.scripts}
    assert "mysql-handshake" in ids
    assert svc.version == "8.0.36"
    assert svc.product == "MySQL"
    # informational: no alert id is emitted
    assert not (ids & fp.EXPOSURE_ALERT_IDS)
    assert svc.confidence != "high"


def test_dispatch_mariadb_strips_legacy_prefix():
    svc = _dispatch(_handshake("5.5.5-10.6.16-MariaDB"))
    assert svc.product == "MariaDB"
    assert svc.version == "10.6.16-MariaDB"
