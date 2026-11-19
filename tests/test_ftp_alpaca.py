"""FTP AUTH TLS probe + ALPACA (CVE-2021-3618) environmental demotion.

No docker, no real network: a loopback asyncio server plays the FTP side, the
same mock pattern test_fingerprint.py uses for the distcc probe. The live
vsftpd (ssl_enable=YES vs NO) verification is run separately.
"""
import asyncio

from servicescan import fingerprint as fp
from servicescan import cve, report
from servicescan.config import ScanConfig
from servicescan.models import Service, CVE


# ---------------------------------------------------------------------------
# loopback FTP mock servers
# ---------------------------------------------------------------------------
async def _ftp_plaintext(reader, writer):
    """FEAT without AUTH TLS, and AUTH TLS rejected -> no explicit TLS."""
    writer.write(b"220 (vsFTPd 3.0.2)\r\n")
    await writer.drain()
    await reader.read(64)                       # FEAT\r\n
    writer.write(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
    await writer.drain()
    await reader.read(64)                       # AUTH TLS\r\n
    writer.write(b"500 Unknown command.\r\n")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()


async def _ftp_feat_authtls(reader, writer):
    """FEAT advertises AUTH TLS -> explicit TLS offered (FEAT path)."""
    writer.write(b"220 (vsFTPd 3.0.5)\r\n")
    await writer.drain()
    await reader.read(64)                       # FEAT\r\n
    writer.write(b"211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()


async def _ftp_fallback_234(reader, writer):
    """FEAT hides it, but AUTH TLS returns 234 -> TLS offered (fallback path)."""
    writer.write(b"220 ready\r\n")
    await writer.drain()
    await reader.read(64)                       # FEAT\r\n
    writer.write(b"211-Features:\r\n PASV\r\n211 End\r\n")
    await writer.drain()
    await reader.read(64)                       # AUTH TLS\r\n
    writer.write(b"234 Proceed with negotiation.\r\n")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()


def _probe(handler, timeout=0.5):
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await fp.ftp_tls_probe("127.0.0.1", port, timeout)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(run())


# ---------------------------------------------------------------------------
# probe behaviour
# ---------------------------------------------------------------------------
def test_ftp_tls_probe_detects_feat_auth_tls():
    assert _probe(_ftp_feat_authtls) is True


def test_ftp_tls_probe_detects_fallback_234():
    assert _probe(_ftp_fallback_234) is True


def test_ftp_tls_probe_plaintext_is_false():
    assert _probe(_ftp_plaintext) is False


def test_ftp_tls_probe_dead_port_is_false():
    # nothing listening -> connect fails -> not TLS (and no exception leaks)
    assert fp.ftp_tls_probe is not None
    assert asyncio.run(fp.ftp_tls_probe("127.0.0.1", 9, 0.3)) is False


def test_ftp_tls_probe_is_read_only():
    # the probe must never send a data-mutating FTP verb; only FEAT / AUTH TLS
    import inspect
    src = inspect.getsource(fp.ftp_tls_probe)
    for verb in ("STOR", "DELE", "RMD", "MKD", "RNFR", "RNTO", "APPE"):
        assert verb not in src


# ---------------------------------------------------------------------------
# ALPACA environmental demotion
# ---------------------------------------------------------------------------
def _alpaca_cve() -> CVE:
    return CVE(id="CVE-2021-3618", source="nvd", cvss=7.4, severity="HIGH",
               summary="ALPACA: cross-protocol TLS attack against vsftpd")


def _refine(handler, make_services, timeout=0.5):
    """Start a mock FTP server, build the services against its port, run the
    ALPACA refinement, and return the (possibly mutated) services."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svcs = make_services(port)
        try:
            await cve.refine_ftp_alpaca(ScanConfig(timeout=timeout),
                                        "127.0.0.1", svcs)
        finally:
            server.close()
            await server.wait_closed()
        return svcs
    return asyncio.run(run())


def test_alpaca_demoted_on_plaintext_ftp():
    def mk(port):
        return [Service(port=port, name="ftp", product="vsftpd",
                        version="3.0.2", state="open", cves=[_alpaca_cve()])]
    svcs = _refine(_ftp_plaintext, mk)
    c = svcs[0].cves[0]
    # canonical values preserved (intel not lost)
    assert c.cvss == 7.4 and c.severity == "HIGH"
    # display demoted
    assert c.effective_cvss == 0.0
    assert c.effective_severity == "LOW"
    assert c.env_note and "ALPACA" in c.env_note
    assert c.disp_cvss() == 0.0
    assert c.disp_severity() == "LOW"


def test_alpaca_kept_when_feat_advertises_tls():
    def mk(port):
        return [Service(port=port, name="ftp", product="vsftpd",
                        version="3.0.4", state="open", cves=[_alpaca_cve()])]
    svcs = _refine(_ftp_feat_authtls, mk)
    c = svcs[0].cves[0]
    assert c.effective_severity == ""      # untouched
    assert c.env_note == ""
    assert c.disp_severity() == "HIGH"


def test_alpaca_kept_on_implicit_ftps_without_probing():
    # implicit FTPS (990) is TLS by definition -> static short-circuit, no probe
    svc = Service(port=990, name="ftps", product="vsftpd", version="3.0.3",
                  state="open", cves=[_alpaca_cve()])
    asyncio.run(cve.refine_ftp_alpaca(ScanConfig(timeout=0.3), "127.0.0.1",
                                      [svc]))
    assert svc.cves[0].effective_severity == ""
    assert svc.cves[0].env_note == ""


def test_alpaca_kept_when_tls_cert_already_grabbed():
    svc = Service(port=21, name="ftp", state="open",
                  tls={"tls_version": "TLSv1.2"}, cves=[_alpaca_cve()])
    asyncio.run(cve.refine_ftp_alpaca(ScanConfig(timeout=0.3), "127.0.0.1",
                                      [svc]))
    assert svc.cves[0].effective_severity == ""


def test_alpaca_ignored_on_non_ftp_service():
    # same CVE id on a non-FTP service must NOT be touched (and must not probe)
    svc = Service(port=80, name="http", state="open", cves=[_alpaca_cve()])
    asyncio.run(cve.refine_ftp_alpaca(ScanConfig(timeout=0.3), "127.0.0.1",
                                      [svc]))
    assert svc.cves[0].effective_severity == ""


def test_refine_noop_without_alpaca():
    other = CVE(id="CVE-2015-1419", source="nvd", cvss=5.0, severity="MEDIUM",
                summary="vsftpd deny_file bypass")
    svc = Service(port=21, name="ftp", state="open", cves=[other])
    asyncio.run(cve.refine_ftp_alpaca(ScanConfig(timeout=0.3), "127.0.0.1",
                                      [svc]))
    assert svc.cves[0].effective_severity == ""


# ---------------------------------------------------------------------------
# display: a demoted CVE keeps its 7.4 score but must NOT render red
# ---------------------------------------------------------------------------
def test_demoted_cve_renders_low_color_despite_high_score():
    from webrecon.utils import C
    # LOW label with a canonical 7.4 score -> gray, not red (the whole point)
    assert report._sev_color("LOW", 7.4) == C.GRY
    # with no label the numeric band still drives color
    assert report._sev_color("", 7.4) == C.RED
