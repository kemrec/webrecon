"""PostgreSQL unauthenticated StartupMessage posture (TCP 5432).

A protocol-3.0 StartupMessage with no password makes the backend declare its
auth method: AuthenticationOk (subtype 0) = pg_hba `trust` = unauthenticated
read/write (the alert); subtypes 3/5/10 or an ErrorResponse = auth enforced
(informational). No credential is ever sent. Loopback mock backend only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _pg(t, body):
    return t + (len(body) + 4).to_bytes(4, "big") + body


_TRUST = (_pg(b"R", (0).to_bytes(4, "big"))
          + _pg(b"S", b"server_version\x00" + b"16.2\x00")
          + _pg(b"Z", b"I"))
_MD5 = _pg(b"R", (5).to_bytes(4, "big") + b"\x01\x02\x03\x04")
_SCRAM = _pg(b"R", (10).to_bytes(4, "big") + b"SCRAM-SHA-256\x00\x00")
_PASSWORD = _pg(b"R", (3).to_bytes(4, "big"))
_ERROR = _pg(b"E", b"SFATAL\x00C28000\x00Mno pg_hba.conf entry for host\x00\x00")


def _pg_server(reply):
    async def handler(reader, writer):
        try:                               # consume the startup message
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            n = int.from_bytes(hdr, "big") - 4
            await asyncio.wait_for(reader.readexactly(max(n, 0)), timeout=2.0)
        except Exception:
            writer.close()
            return
        writer.write(reply)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(reply):
    async def run():
        srv = await asyncio.start_server(_pg_server(reply), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.postgres_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- wire format ------------------------------------------------------------
def test_startup_message_layout():
    m = fp._pg_startup("postgres", "postgres")
    assert int.from_bytes(m[0:4], "big") == len(m)          # self-inclusive len
    assert m[4:8] == (196608).to_bytes(4, "big")            # protocol 3.0
    assert b"user\x00postgres\x00" in m
    assert m.endswith(b"\x00")                              # trailing terminator


# --- probe ------------------------------------------------------------------
def test_trust_detected_with_version():
    res = _probe(_TRUST)
    assert res["auth"] == "trust"
    assert res["version"] == "16.2"


def test_md5_is_auth_enforced():
    assert _probe(_MD5)["auth"] == "md5"


def test_scram_is_auth_enforced():
    assert _probe(_SCRAM)["auth"] == "scram"


def test_error_response_is_enforced_with_sqlstate():
    res = _probe(_ERROR)
    assert res["auth"] == "enforced"
    assert res["sqlstate"] == "28000"


def test_non_postgres_port_is_none():
    async def silent(reader, writer):
        writer.close()
    async def run():
        srv = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.postgres_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    assert asyncio.run(run()) is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(reply):
    svc = Service(port=0, name="postgresql", state="open")

    async def run():
        srv = await asyncio.start_server(_pg_server(reply), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_trust_is_alert():
    svc = _dispatch(_TRUST)
    ids = {s["id"] for s in svc.scripts}
    assert "postgres-trust-unauth" in ids
    assert "postgres-trust-unauth" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"
    assert svc.version == "16.2"
    assert svc.product == "PostgreSQL"


def test_dispatch_scram_is_informational():
    svc = _dispatch(_SCRAM)
    ids = {s["id"] for s in svc.scripts}
    assert "postgres-auth" in ids
    assert "postgres-trust-unauth" not in ids
    assert svc.confidence != "high"
