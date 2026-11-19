import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _probe(handler, probe, timeout=0.5):
    """Serve `handler` on loopback, run `probe` against it, return the result."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await probe("127.0.0.1", port, timeout)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(run())


def _responder(payload: bytes):
    async def handler(reader, writer):
        try:
            await reader.read(256)          # consume the probe request
        except Exception:
            pass
        writer.write(payload)
        await writer.drain()
        writer.close()
    return handler


# --- Redis -----------------------------------------------------------------
def test_redis_open_extracts_version():
    body = b"$120\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
    assert _probe(_responder(body), fp.redis_probe) == ("open", "7.2.4")


def test_redis_auth_required():
    assert _probe(_responder(b"-NOAUTH Authentication required.\r\n"),
                  fp.redis_probe) == ("auth", "")


def test_redis_protected_mode_is_not_open():
    body = b"-DENIED Redis is running in protected mode\r\n"
    assert _probe(_responder(body), fp.redis_probe) == ("auth", "")


def test_redis_non_redis_is_none():
    assert _probe(_responder(b"SSH-2.0-OpenSSH_9.0\r\n"), fp.redis_probe) is None


# --- memcached --------------------------------------------------------------
def test_memcached_open_extracts_version():
    assert _probe(_responder(b"VERSION 1.6.21\r\n"),
                  fp.memcached_probe) == ("open", "1.6.21")


def test_memcached_sasl_error_is_auth():
    assert _probe(_responder(b"ERROR\r\n"), fp.memcached_probe) == ("auth", "")


# --- MongoDB ----------------------------------------------------------------
def test_mongo_listdb_message_is_wellformed():
    msg = fp._mongo_listdb_msg()
    # messageLength header must equal the real length, opcode must be OP_MSG
    import struct
    length, _req, _resp, opcode = struct.unpack("<iiii", msg[:16])
    assert length == len(msg)
    assert opcode == 2013
    assert b"listDatabases" in msg and b"admin" in msg


def test_mongo_open_when_listing_returns_databases():
    body = b"\x00" * 20 + b"databases" + b"\x00" * 8     # >=16 bytes, has marker
    assert _probe(_responder(body), fp.mongodb_probe) == ("open", "")


def test_mongo_auth_required():
    body = b"\x00" * 20 + b"not authorized on admin" + b"\x00"
    assert _probe(_responder(body), fp.mongodb_probe) == ("auth", "")


def test_mongo_short_or_unrelated_is_none():
    assert _probe(_responder(b"hi"), fp.mongodb_probe) is None


# --- check_exposure wiring --------------------------------------------------
def _check(svc, handler):
    """Point a service at a mock server on an ephemeral port and run the check."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        svc.port = server.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=0.5),
                                    "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())
    return svc


def test_check_exposure_marks_redis_unauth():
    # name triggers the redis branch regardless of (ephemeral) port
    svc = Service(port=0, name="redis", state="open")
    _check(svc, _responder(b"# Server\r\nredis_version:7.0.0\r\n"))
    ids = [sc["id"] for sc in svc.scripts]
    assert "redis-unauth" in ids
    assert svc.version == "7.0.0"
    assert "exposure" in svc.sources
    assert "UNAUTHENTICATED" in svc.extrainfo


def test_check_exposure_auth_does_not_flag_unauth():
    svc = Service(port=0, name="redis", state="open")
    _check(svc, _responder(b"-NOAUTH Authentication required.\r\n"))
    ids = [sc["id"] for sc in svc.scripts]
    assert "redis-unauth" not in ids
    assert "redis-auth" in ids


def test_check_exposure_ignores_unrelated_service():
    svc = Service(port=0, name="ssh", state="open")
    _check(svc, _responder(b"SSH-2.0-OpenSSH_9.0\r\n"))
    assert svc.scripts == []
