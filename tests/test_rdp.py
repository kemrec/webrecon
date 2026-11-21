"""RDP security-negotiation posture (TCP 3389).

An X.224 Connection Request with an RDP Negotiation Request makes the server
reveal its negotiated security without authenticating: HYBRID/HYBRID_EX = NLA
in use, SSL = TLS without NLA, standard RDP = no TLS, or a failure/none.
NLA-not-enforced is reported informationally (hardening gap, not a breach).
Loopback mock server only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

_X224_CC = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00"   # TPKT + CC, LI=14


def _rsp(protocol):
    return _X224_CC + b"\x02\x00\x08\x00" + protocol.to_bytes(4, "little")


def _fail(code):
    return _X224_CC + b"\x03\x00\x08\x00" + code.to_bytes(4, "little")


_NONE = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"       # plain CC, no neg


def _server(resp):
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(256), timeout=2.0)
        except Exception:
            pass
        writer.write(resp)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(resp):
    async def run():
        srv = await asyncio.start_server(_server(resp), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.rdp_probe("127.0.0.1", port, 1.0)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- probe ------------------------------------------------------------------
def test_rsp_hybrid_nla():
    assert _probe(_rsp(2)) == {"kind": "rsp", "protocol": 2}


def test_rsp_ssl_only():
    assert _probe(_rsp(1)) == {"kind": "rsp", "protocol": 1}


def test_failure_hybrid_required():
    assert _probe(_fail(5)) == {"kind": "failure", "code": 5}


def test_legacy_no_negotiation():
    assert _probe(_NONE) == {"kind": "none"}


def test_non_rdp_is_none():
    assert _probe(b"HTTP/1.1 400 Bad Request\r\n\r\n") is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(resp):
    svc = Service(port=0, name="ms-wbt-server", state="open")

    async def run():
        srv = await asyncio.start_server(_server(resp), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_nla_in_use_is_good():
    svc = _dispatch(_rsp(2))
    out = next(s["output"] for s in svc.scripts if s["id"] == "rdp-nla")
    assert "in use" in out and "good posture" in out
    assert not ({s["id"] for s in svc.scripts} & fp.EXPOSURE_ALERT_IDS)
    assert svc.product == "Microsoft Terminal Services"


def test_dispatch_nla_not_enforced_is_flagged():
    svc = _dispatch(_rsp(1))                 # TLS only, no NLA
    out = next(s["output"] for s in svc.scripts if s["id"] == "rdp-nla")
    assert "NOT enforced" in out
    # informational hardening note, not an alert
    assert not ({s["id"] for s in svc.scripts} & fp.EXPOSURE_ALERT_IDS)


def test_dispatch_hybrid_required_is_good():
    svc = _dispatch(_fail(5))
    out = next(s["output"] for s in svc.scripts if s["id"] == "rdp-nla")
    assert "requires Network Level Authentication" in out
