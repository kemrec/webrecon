"""SMB internal-network triage (TCP 445). Dependency-free, read-only: an
anonymous SMB2 negotiate + session-setup (NTLM type-1 only, never type-3) to
read signing posture and the NTLM CHALLENGE (OS build + AD/NetBIOS names), plus
a separate SMB1 negotiate for SMBv1 detection. Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- build a realistic NTLMSSP CHALLENGE (type 2) ---------------------------
def _mk_ntlm_type2() -> bytes:
    def av(aid, s):
        b = s.encode("utf-16-le")
        return aid.to_bytes(2, "little") + len(b).to_bytes(2, "little") + b
    ti = (av(2, "CORP") + av(1, "DC01") + av(4, "corp.local")
          + av(3, "DC01.corp.local") + b"\x00\x00\x00\x00")   # MsvAvEOL
    flags = 0x02000000 | 0x00800000                           # VERSION | TARGET_INFO
    msg = (b"NTLMSSP\x00" + (2).to_bytes(4, "little")
           + b"\x00" * 8                                       # TargetNameFields
           + flags.to_bytes(4, "little")
           + b"\x11" * 8                                       # ServerChallenge
           + b"\x00" * 8)                                      # Reserved
    ti_off = len(msg) + 8 + 8                                  # after TI fields + Version
    msg += (len(ti).to_bytes(2, "little") + len(ti).to_bytes(2, "little")
            + ti_off.to_bytes(4, "little"))
    msg += bytes([10, 0]) + (19041).to_bytes(2, "little") + b"\x00\x00\x00\x0f"
    msg += ti
    return msg


def test_parse_ntlm_type2_extracts_os_and_names():
    d = fp._parse_ntlm_type2(b"....garbage...." + _mk_ntlm_type2() + b"trailer")
    assert d["os"] == "10.0.19041"
    assert d["nb_domain"] == "CORP"
    assert d["nb_computer"] == "DC01"
    assert d["dns_domain"] == "corp.local"
    assert d["dns_computer"] == "DC01.corp.local"


def test_ntlm_type1_and_spnego_wrap_shape():
    t1 = fp._ntlm_type1()
    assert t1.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")
    wrapped = fp._spnego_ntlm(t1)
    assert wrapped[0] == 0x60                       # GSS-API application tag
    assert b"NTLMSSP\x00" in wrapped                # token carried inside


# --- mock SMB server --------------------------------------------------------
def _neg_response(secmode: int, dialect: int) -> bytes:
    hdr = b"\xfeSMB" + b"\x00" * 60                 # 64-byte header (content irrelevant)
    body = ((65).to_bytes(2, "little") + secmode.to_bytes(2, "little")
            + dialect.to_bytes(2, "little") + b"\x00" * 60)
    return hdr + body                               # SecurityMode at offset 66, dialect 68


def _sess_response() -> bytes:
    return b"\xfeSMB" + b"\x00" * 60 + b"\x09\x00" + _mk_ntlm_type2()


def _smb1_response() -> bytes:
    return b"\xffSMB" + b"\x72" + b"\x00" * 27      # SMB1 NEGOTIATE reply (v1 alive)


def _smb_server(mode: str):
    # modes: relay (signing optional), secure (signing required), smbv1, notsmb
    secmode = {"relay": 0x01, "secure": 0x03, "smbv1": 0x03}.get(mode, 0x03)

    async def handler(reader, writer):
        try:
            while True:
                try:
                    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
                except Exception:
                    break
                n = int.from_bytes(hdr[1:4], "big")
                msg = await asyncio.wait_for(reader.readexactly(n), timeout=2.0)
                if mode == "notsmb":
                    writer.write(fp._nbss(b"\x00\x00\x00\x00"))
                    await writer.drain()
                    break
                if msg[:4] == b"\xfeSMB":
                    cmd = int.from_bytes(msg[12:14], "little")
                    if cmd == 0x0000:
                        writer.write(fp._nbss(_neg_response(secmode, 0x0311)))
                    elif cmd == 0x0001:
                        writer.write(fp._nbss(_sess_response()))
                    else:
                        break
                    await writer.drain()
                elif msg[:4] == b"\xffSMB":
                    if mode == "smbv1":
                        writer.write(fp._nbss(_smb1_response()))
                        await writer.drain()
                    break                           # non-smbv1: no SMB1 answer
                else:
                    break
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_smb_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.smb_probe("127.0.0.1", port, timeout)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_relay_signing_not_required_and_ntlm_leak():
    r = _probe("relay")
    assert r is not None
    assert r["signing_required"] is False and r["signing_enabled"] is True
    assert r["dialect"] == 0x0311
    assert r["ntlm"]["os"] == "10.0.19041" and r["ntlm"]["dns_domain"] == "corp.local"
    assert r["smbv1"] is False


def test_probe_secure_signing_required():
    r = _probe("secure")
    assert r["signing_required"] is True


def test_probe_smbv1_enabled():
    r = _probe("smbv1")
    assert r["smbv1"] is True


def test_probe_non_smb_is_none():
    assert _probe("notsmb") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="microsoft-ds"):
    svc = Service(port=0, name=name, state="open")

    async def run():
        srv = await asyncio.start_server(_smb_server(mode), "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_relay_is_alert_plus_ntlm_recon():
    svc = _check("relay")
    ids = {s["id"] for s in svc.scripts}
    assert "smb-signing-not-required" in ids
    assert "smb-signing-not-required" in fp.EXPOSURE_ALERT_IDS
    assert "smb-ntlm-info" in ids
    assert "smb-ntlm-info" not in fp.EXPOSURE_ALERT_IDS      # recon is informational
    assert svc.product == "Windows" and svc.version == "10.0.19041"


def test_dispatch_smbv1_is_alert():
    svc = _check("smbv1")
    ids = {s["id"] for s in svc.scripts}
    assert "smbv1-enabled" in ids
    assert "smbv1-enabled" in fp.EXPOSURE_ALERT_IDS


def test_dispatch_secure_is_informational_not_alert():
    svc = _check("secure")
    ids = {s["id"] for s in svc.scripts}
    assert "smb-signing-required" in ids
    assert "smb-signing-required" not in fp.EXPOSURE_ALERT_IDS
    assert "smb-signing-not-required" not in ids
