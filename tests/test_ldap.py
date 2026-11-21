"""LDAP anonymous-bind exposure (TCP 389 / 636). Dependency-free BER: an
anonymous simple bind + rootDSE read is AD recon; an anonymous naming-context
search that returns objects means anonymous directory reads are enabled
(alert). All reads. Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- BER LDAPMessage builders for the mock server ---------------------------
def _bind_resp(msgid, rc):
    br = (fp._ber_tlv(0x0a, bytes([rc])) + fp._ber_tlv(0x04, b"")
          + fp._ber_tlv(0x04, b""))
    return fp._ber_tlv(0x30, fp._ber_int(msgid) + fp._ber_tlv(0x61, br))


def _attr(t, vals):
    valset = fp._ber_tlv(0x31, b"".join(fp._ber_tlv(0x04, v.encode()) for v in vals))
    return fp._ber_tlv(0x30, fp._ber_tlv(0x04, t.encode()) + valset)


def _entry(msgid, dn, attrs):
    e = (fp._ber_tlv(0x04, dn.encode())
         + fp._ber_tlv(0x30, b"".join(_attr(t, v) for t, v in attrs.items())))
    return fp._ber_tlv(0x30, fp._ber_int(msgid) + fp._ber_tlv(0x64, e))


def _done(msgid):
    d = fp._ber_tlv(0x0a, b"\x00") + fp._ber_tlv(0x04, b"") + fp._ber_tlv(0x04, b"")
    return fp._ber_tlv(0x30, fp._ber_int(msgid) + fp._ber_tlv(0x65, d))


async def _read_one(reader):
    """Consume one BER TLV (an LDAP request) so the stream stays aligned."""
    hdr = await asyncio.wait_for(reader.readexactly(2), timeout=2.0)
    l = hdr[1]
    if l & 0x80:
        ext = await asyncio.wait_for(reader.readexactly(l & 0x7f), timeout=2.0)
        l = int.from_bytes(ext, "big")
    await asyncio.wait_for(reader.readexactly(l), timeout=2.0)


_ROOTDSE = {"namingContexts": ["DC=corp,DC=local"],
            "dnsHostName": ["dc01.corp.local"],
            "domainControllerFunctionality": ["7"],
            "forestFunctionality": ["7"]}


def _ldap_server(mode):
    async def handler(reader, writer):
        try:
            await _read_one(reader)                       # BindRequest
            if mode == "notldap":
                writer.write(b"notldapresponse!")
                await writer.drain()
                writer.close()
                return
            rc = 49 if mode == "bind_refused" else 0
            writer.write(_bind_resp(1, rc))
            await writer.drain()
            if rc != 0:
                writer.close()
                return
            await _read_one(reader)                       # rootDSE search
            writer.write(_entry(2, "", _ROOTDSE))
            writer.write(_done(2))
            await writer.drain()
            await _read_one(reader)                       # naming-context search
            if mode == "anon_read":
                writer.write(_entry(3, "CN=Administrator,DC=corp,DC=local",
                                    {"cn": ["Administrator"]}))
                writer.write(_entry(3, "CN=krbtgt,DC=corp,DC=local",
                                    {"cn": ["krbtgt"]}))
            writer.write(_done(3))
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_ldap_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.ldap_probe("127.0.0.1", port, timeout, False)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_anonymous_read_enabled():
    r = _probe("anon_read")
    assert r is not None
    assert r["anon_bind"] is True and r["anon_read"] is True
    assert r["rootdse"]["namingContexts"] == ["DC=corp,DC=local"]
    assert r["rootdse"]["dnsHostName"] == ["dc01.corp.local"]


def test_probe_rootdse_only_no_anon_read():
    r = _probe("rootdse_only")
    assert r["anon_bind"] is True and r["anon_read"] is False
    assert r["rootdse"]["dnsHostName"] == ["dc01.corp.local"]


def test_probe_bind_refused():
    r = _probe("bind_refused")
    assert r is not None and r["anon_bind"] is False


def test_probe_non_ldap_is_none():
    assert _probe("notldap") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="ldap"):
    svc = Service(port=0, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(_ldap_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_anon_read_is_alert():
    svc = _check("anon_read")
    ids = {s["id"] for s in svc.scripts}
    assert "ldap-anonymous-read" in ids
    assert "ldap-anonymous-read" in fp.EXPOSURE_ALERT_IDS
    assert "ldap-rootdse" in ids
    assert "ldap-rootdse" not in fp.EXPOSURE_ALERT_IDS
    assert svc.product == "Active Directory"


def test_dispatch_rootdse_only_informational():
    svc = _check("rootdse_only")
    ids = {s["id"] for s in svc.scripts}
    assert "ldap-rootdse" in ids
    assert "ldap-anonymous-read" not in ids


def test_dispatch_bind_refused_informational():
    svc = _check("bind_refused")
    ids = {s["id"] for s in svc.scripts}
    assert "ldap-bind-refused" in ids
    assert "ldap-rootdse" not in ids
