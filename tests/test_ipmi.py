import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _open_session_response(status: int,
                           msid_wire: bytes = b"\x11\x22\x33\x44") -> bytes:
    body = (
        b"\x00"                 # message tag
        + bytes([status])       # RMCP+ status code
        + b"\x00\x00"           # max priv, reserved
        + b"\xa0\xa2\xa3\xa4"   # remote console session id (echo)
        + msid_wire             # managed system session id (little-endian wire)
        + b"\x00\x00\x00\x08\x01\x00\x00\x00"   # auth payload
        + b"\x01\x00\x00\x08\x01\x00\x00\x00"   # integrity payload
        + b"\x02\x00\x00\x08\x01\x00\x00\x00"   # confidentiality payload
    )
    header = (
        b"\x06\x00\xff\x07"     # RMCP
        b"\x06"                 # auth type
        b"\x11"                 # payload type: Open Session Response
        b"\x00\x00\x00\x00"     # session id
        b"\x00\x00\x00\x00"     # session seq
        + len(body).to_bytes(2, "little")
    )
    return header + body


# --- request packet shape ---------------------------------------------------
def test_open_session_request_is_wellformed():
    pkt = fp._IPMI_OPEN_SESSION_REQ
    assert pkt[:4] == b"\x06\x00\xff\x07"       # RMCP header
    assert pkt[5] == 0x10                        # payload type: open session req
    assert pkt[14:16] == b"\x20\x00"             # payload length 32 (LE)
    assert len(pkt) == 16 + 32                   # header + 32-byte body
    # payload type bytes identify auth(0) / integrity(1) / confidentiality(2)
    assert pkt[24] == 0x00 and pkt[32] == 0x01 and pkt[40] == 0x02
    # each payload's algorithm byte (offset +4 within the 8-byte block) is 0
    assert pkt[28] == 0x00 and pkt[36] == 0x00 and pkt[44] == 0x00


# --- response parsing -------------------------------------------------------
def test_parse_cipher_zero_accepted():
    res = fp._ipmi_parse_open_session(_open_session_response(0x00))
    assert res is not None and res[0] == "open"
    assert res[1] == "44332211"                  # msid is little-endian on wire


def test_parse_cipher_zero_refused():
    # status 0x01 (insufficient resources) / any non-zero => present but refused
    assert fp._ipmi_parse_open_session(_open_session_response(0x01)) == ("auth", "")


def test_parse_rejects_non_ipmi():
    assert fp._ipmi_parse_open_session(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert fp._ipmi_parse_open_session(b"\x06\x00\xff\x07short") is None
    # right RMCP header but wrong payload type (not an open-session response)
    bad = b"\x06\x00\xff\x07\x06\x10" + b"\x00" * 12
    assert fp._ipmi_parse_open_session(bad) is None


# --- live UDP probe end-to-end ---------------------------------------------
def _serve_ipmi(status: int | None):
    """A UDP BMC that answers an Open Session Request with the given status
    (None => stays silent, i.e. not IPMI)."""
    async def run():
        loop = asyncio.get_event_loop()

        class Bmc(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                if status is not None and data[:4] == b"\x06\x00\xff\x07":
                    self.t.sendto(_open_session_response(status), addr)

        transport, _ = await loop.create_datagram_endpoint(
            Bmc, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("sockname")[1]
        try:
            return await fp.ipmi_cipher_zero_probe("127.0.0.1", port, 1.0)
        finally:
            transport.close()
    return asyncio.run(run())


def test_probe_open_when_accepted():
    res = _serve_ipmi(0x00)
    assert res is not None and res[0] == "open"


def test_probe_auth_when_refused():
    assert _serve_ipmi(0x01) == ("auth", "")


def test_probe_timeout_returns_none():
    async def run():
        return await fp.ipmi_cipher_zero_probe("127.0.0.1", 59997, 0.3)
    assert asyncio.run(run()) is None


# --- host-level wiring ------------------------------------------------------
def _run_exposure(monkeypatch, ipmi_result):
    async def fake_ipmi(host, port, timeout):
        return ipmi_result

    async def none_probe(host, port, timeout):
        return None

    monkeypatch.setattr(fp, "ipmi_cipher_zero_probe", fake_ipmi)
    monkeypatch.setattr(fp, "snmp_probe", none_probe)
    monkeypatch.setattr(fp, "wsdiscovery_probe", none_probe)

    async def run():
        services = [Service(port=22, name="ssh", state="open")]
        cfg = ScanConfig(target="x", timeout=1.0, concurrency=5)
        await fp.run_exposure_checks(cfg, "127.0.0.1", services)
        return services

    services = asyncio.run(run())
    return next((s for s in services if s.port == 623 and s.proto == "udp"), None)


def test_run_exposure_checks_marks_cipher_zero(monkeypatch):
    svc = _run_exposure(monkeypatch, ("open", "44332211"))
    assert svc is not None
    ids = {sc["id"] for sc in svc.scripts}
    assert "ipmi-cipher-zero" in ids
    assert "ipmi-cipher-zero" in fp.EXPOSURE_ALERT_IDS
    assert "cipher-zero" in svc.extrainfo


def test_run_exposure_checks_detected_only_is_not_an_alert(monkeypatch):
    svc = _run_exposure(monkeypatch, ("auth", ""))
    assert svc is not None
    ids = {sc["id"] for sc in svc.scripts}
    assert ids == {"ipmi-detected"}
    assert "ipmi-detected" not in fp.EXPOSURE_ALERT_IDS
