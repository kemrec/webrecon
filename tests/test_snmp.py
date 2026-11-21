import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- BER encoder round-trips ----------------------------------------------
def test_ber_len_short_and_long_form():
    assert fp._ber_len(5) == b"\x05"
    assert fp._ber_len(0x7F) == b"\x7f"
    assert fp._ber_len(0x80) == b"\x81\x80"      # long form, one length byte
    assert fp._ber_len(0x1234) == b"\x82\x12\x34"


def test_ber_int_minimal_and_sign_safe():
    assert fp._ber_int(0) == b"\x02\x01\x00"
    assert fp._ber_int(1) == b"\x02\x01\x01"
    assert fp._ber_int(0x80) == b"\x02\x02\x00\x80"   # leading 0 keeps it positive
    assert fp._ber_int(0x01020304) == b"\x02\x04\x01\x02\x03\x04"


def test_ber_oid_sysdescr():
    # 1.3.6.1.2.1.1.1.0 -> first byte 40*1+3=0x2b, rest single-byte
    assert fp._ber_oid(fp._SYSDESCR_OID) == b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"


def test_ber_oid_multibyte_subid():
    # a sub-identifier >= 128 uses base-128 continuation bytes
    oid = fp._ber_oid((1, 3, 6, 1, 4, 1, 2021))   # 2021 -> 0x8f 0x65
    assert oid.endswith(b"\x8f\x65")


# --- GetRequest packet shape ------------------------------------------------
def test_snmp_get_request_wellformed():
    pkt = fp._snmp_get("public", fp._SYSDESCR_OID, 1, 0x01020304)
    children = fp._ber_split(pkt[2:] if pkt[1] < 0x80 else pkt[3:])
    # top is a SEQUENCE; its body is [version, community, GetRequest-PDU]
    assert pkt[0] == 0x30
    assert children[0] == (0x02, b"\x01")                 # version v2c = 1
    assert children[1] == (0x04, b"public")               # community
    assert children[2][0] == 0xA0                         # GetRequest PDU tag


# --- response parsing -------------------------------------------------------
def _getresponse(community: bytes, sysdescr: bytes, errstat: int = 0) -> bytes:
    oid = fp._ber_oid(fp._SYSDESCR_OID)
    varbind = fp._ber_tlv(0x30, oid + fp._ber_tlv(0x04, sysdescr))
    pdu = fp._ber_tlv(0xA2,                                # 0xA2 = GetResponse
                      fp._ber_int(0x01020304) + fp._ber_int(errstat)
                      + fp._ber_int(0) + fp._ber_tlv(0x30, varbind))
    msg = fp._ber_int(1) + fp._ber_tlv(0x04, community) + pdu
    return fp._ber_tlv(0x30, msg)


def test_snmp_sysdescr_extracts_value():
    pkt = _getresponse(b"public", b"Linux router 5.10 #1 SMP")
    assert fp._snmp_sysdescr(pkt) == "Linux router 5.10 #1 SMP"


def test_snmp_sysdescr_ignores_error_status():
    pkt = _getresponse(b"public", b"x", errstat=2)       # noSuchName etc.
    assert fp._snmp_sysdescr(pkt) is None


def test_snmp_sysdescr_rejects_non_snmp():
    assert fp._snmp_sysdescr(b"\x16\x03\x01not tls really") is None
    assert fp._snmp_sysdescr(b"") is None


# --- live UDP probe end-to-end ---------------------------------------------
def _serve_snmp(reply_for_community: bytes | None):
    """A UDP agent that answers any GetRequest carrying the given community."""
    async def run(probe):
        loop = asyncio.get_event_loop()

        class Agent(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                if reply_for_community and reply_for_community in data:
                    self.t.sendto(
                        _getresponse(reply_for_community, b"TestAgent v1.0"), addr)

        transport, _ = await loop.create_datagram_endpoint(
            Agent, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        try:
            return await probe("127.0.0.1", port, 1.0)
        finally:
            transport.close()
    return asyncio.run(run(fp.snmp_probe))


def test_snmp_probe_open_with_public():
    res = _serve_snmp(b"public")
    assert res is not None
    assert res["community"] == "public"
    assert res["sysdescr"] == "TestAgent v1.0"


def test_snmp_probe_none_when_community_mismatch():
    # agent only answers "s3cr3t"; neither public nor private match
    assert _serve_snmp(b"s3cr3t") is None


def test_snmp_probe_timeout_returns_none():
    async def run():
        return await fp.snmp_probe("127.0.0.1", 59998, 0.3)
    assert asyncio.run(run()) is None


# --- host-level wiring in run_exposure_checks -------------------------------
def test_run_exposure_checks_marks_snmp(monkeypatch):
    async def fake_snmp(host, port, timeout):
        return {"community": "public", "sysdescr": "Cisco IOS XE  17.3",
                "version": "2c"}

    async def no_wsd(host, port, timeout):
        return None

    monkeypatch.setattr(fp, "snmp_probe", fake_snmp)
    monkeypatch.setattr(fp, "wsdiscovery_probe", no_wsd)

    async def run():
        services = [Service(port=22, name="ssh", state="open")]
        cfg = ScanConfig(target="x", timeout=1.0, concurrency=5)
        await fp.run_exposure_checks(cfg, "127.0.0.1", services)
        return services

    services = asyncio.run(run())
    snmp = next((s for s in services if s.port == 161 and s.proto == "udp"), None)
    assert snmp is not None
    ids = {sc["id"] for sc in snmp.scripts}
    assert "snmp-unauth" in ids
    assert "snmp-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "public" in snmp.extrainfo
    # sysDescr whitespace is collapsed into the one-line output
    assert "Cisco IOS XE 17.3" in snmp.scripts[0]["output"]
